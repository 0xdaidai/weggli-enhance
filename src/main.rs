/*
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

extern crate clap;
#[macro_use]
extern crate log;
extern crate rayon;
extern crate simplelog;
extern crate walkdir;

use colored::Colorize;
use rayon::iter::ParallelBridge;
use rayon::prelude::*;
use rayon::Scope;
use fancy_regex::Regex;
use std::cell::RefCell;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{mpsc, Arc};
use std::{collections::HashMap, path::Path, vec};
use std::{collections::HashSet, fs};
use std::{io::prelude::*, path::PathBuf};
use thread_local::ThreadLocal;
use tree_sitter::Tree;
use walkdir::WalkDir;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;

use weggli_enhance::RegexMap;
use weggli_enhance::parse_search_pattern;
use weggli_enhance::query::QueryTree;
use weggli_enhance::result::QueryResult;
mod cli;
use serde_sarif::sarif;
use serde_sarif::sarif::{ReportingDescriptor};

fn main() {
    reset_signal_pipe_handler();

    let args = cli::parse_arguments();

    if args.force_color {
        colored::control::set_override(true)
    }

    // Verify that the --include and --exclude regexes are valid.
    let helper_regex = |v: &[String]| -> Vec<Regex> {
        v.iter()
            .map(|s| {
                let r = Regex::new(s);
                match r {
                    Ok(regex) => regex,
                    Err(e) => {
                        eprintln!("Regex error {}", e);
                        std::process::exit(1)
                    }
                }
            })
            .collect()
    };

    let mut descriptors = vec![];
    let mut results = vec![];
    for rules in rule_path_seek(args.rule_path.as_path()) {
        info!("[+] Issue loading: {}", rules.issue.blue());
        let level = match rules.level {
            Some(Level::Error) => "error",
            Some(Level::Warning)  => "warning",
            Some(Level::Note)  => "note",
            None => "none",
        };
        descriptors.push(
            sarif::ReportingDescriptorBuilder::default()
                .name(rules.issue.clone())
                .id(rules.issue.clone())
                .default_configuration(sarif::ReportingConfigurationBuilder::default().enabled(true).level(level).build().unwrap())
                .build()
                .unwrap(),
        );


        let mut works: Vec<WorkItem> = vec![];

        for rule in rules.rules {
            // Keep track of all variables used in the input pattern(s)
            let mut variables = HashSet::new();

            // Validate all regular expressions
            let regex_constraints = process_regexes(&rule.regexes).unwrap_or_else(|e| {
                let msg = match e {
                    RegexError::InvalidArg(s) => format!(
                        "'{}' is not a valid argument of the form var=regex",
                        s.red()
                    ),
                    RegexError::InvalidRegex(s) => format!("Regex error {}", s),
                };
                eprintln!("{}", msg);
                std::process::exit(1)
            });

            // let mut reason = format!("{}:{}", rule.reason, rules.issue);

            // Normalize all patterns and translate them into QueryTrees
            // We also extract the identifiers at this point
            // to use them for file filtering later on.
            // Invalid patterns trigger a process exit in validate_query so
            // after this point we now that all patterns are valid.
            // The loop also fills the `variables` set with used variable names.
            let work_items: Vec<WorkItem> = rule
                .patterns
                .iter()
                .map(|pattern| {
                    match parse_search_pattern(
                        pattern,
                        args.force_query,
                        Some(regex_constraints.clone()),
                    ) {
                        Ok(qt) => {
                            let identifiers = qt.identifiers();
                            variables.extend(qt.variables());
                            WorkItem {
                                qt,
                                identifiers,
                                reason: rule.reason.clone(),
                                issue: rules.issue.clone(),
                            }
                        }
                        Err(qe) => {
                            eprintln!("{}", qe.message);
                            if parse_search_pattern(
                                pattern,
                                args.force_query,
                                Some(regex_constraints.clone()),
                            )
                            .is_ok()
                            {
                                eprintln!(
                                    "{} This query is valid in C++ mode (-X)",
                                    "Note:".bold()
                                );
                            }
                            std::process::exit(1);
                        }
                    }
                })
                .collect();
            works.extend(work_items);

            for v in regex_constraints.variables() {
                if !variables.contains(v) {
                    eprintln!("'{}' is not a valid query variable", v.red());
                    std::process::exit(1)
                }
            }

            let exclude_re = helper_regex(&args.exclude);
            let include_re = helper_regex(&args.include);

            // Collect and filter our input file set.
            let mut files: Vec<PathBuf> = iter_files(&args.code_path, args.extensions.clone())
                .map(|d| d.into_path())
                .collect();
            if !exclude_re.is_empty() || !include_re.is_empty() {
                // Filter files based on include and exclude regexes
                files.retain(|f| {
                    if exclude_re.iter().any(|r| r.is_match(&f.to_string_lossy()).unwrap()) {
                        return false;
                    }
                    if include_re.is_empty() {
                        return true;
                    }
                    include_re.iter().any(|r| r.is_match(&f.to_string_lossy()).unwrap())
                });
            }

            info!("parsing {} files", files.len());
            if files.is_empty() {
                eprintln!("{}", String::from("No files to parse. Exiting...").red());
                std::process::exit(1)
            }

            // The main parallelized work pipeline
            rayon::scope(|s| {
                // spin up channels for worker communication
                let (ast_tx, ast_rx) = mpsc::channel();
                let (results_tx, results_rx) = mpsc::channel();

                // avoid lifetime issues
                let w = &works;

                let options = Options {
                    limit: args.limit,
                    unique: args.unique,
                };
                // Spawn worker to iterate through files, parse potential matches and forward ASTs
                s.spawn(move |_: &Scope<'_>| parse_files_worker(files, ast_tx, w));

                // Run search queries on ASTs and apply CLI constraints
                // on the results. For single query executions, we can
                // directly print any remaining matches. For multi
                // query runs we forward them to our next worker function
                s.spawn(move |_: &Scope<'_>| {
                    execute_queries_worker(ast_rx, results_tx, w, options)
                });
                results.extend(results_rx.iter());
            });
        }

    }
    // deal with multiple worker's results
    match args.output_path {
        Some(ref path) => {
            // println!("{}", "output branch");
            let mut tmp_path = PathBuf::from(path);
            if tmp_path.is_dir() {
                if tmp_path.is_absolute() {
                    tmp_path.push("results.sarif");
                } else {
                    tmp_path = std::env::current_dir()
                        .unwrap()
                        .join(path)
                        .join("results.sarif")
                }
            } else {
                if !tmp_path.is_absolute() {
                    tmp_path = std::env::current_dir().unwrap().join(path)
                }
            }
            results_collector(
                results,
                descriptors.clone(),
                true,
                Some(tmp_path),
            );
        }
        None => {
            results_collector(
                results,
                descriptors.clone(),
                false,
                None,
            );
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Rules {
    pub issue: String,
    pub description: String,
    pub level: Option<Level>,
    pub rules: Vec<Rule>,
}

#[derive(PartialEq, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warning,
    Note,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Rule {
    pub reason: String,
    pub regexes: Vec<String>,
    pub patterns: Vec<String>,
}

enum RegexError {
    InvalidArg(String),
    InvalidRegex(fancy_regex::Error),
}

impl From<fancy_regex::Error> for RegexError {
    fn from(err: fancy_regex::Error) -> RegexError {
        RegexError::InvalidRegex(err)
    }
}

/// Validate all passed regexes and compile them.
/// Returns an error if an invalid regex is supplied otherwise return a RegexMap
fn process_regexes(regexes: &[String]) -> Result<RegexMap, RegexError> {
    let mut result = HashMap::new();

    for r in regexes {
        let mut s = r.splitn(2, '=');
        let var = s.next().ok_or_else(|| RegexError::InvalidArg(r.clone()))?;
        let raw_regex = s.next().ok_or_else(|| RegexError::InvalidArg(r.clone()))?;

        let mut normalized_var = if var.starts_with('$') {
            var.to_string()
        } else {
            "$".to_string() + var
        };
        let negative = normalized_var.ends_with('!');

        if negative {
            normalized_var.pop(); // remove !
        }

        let regex = Regex::new(raw_regex)?;
        result.insert(normalized_var, (negative, regex));
    }
    Ok(RegexMap::new(result))
}

/// Recursively iterate through all files under `path` that match an ending listed in `extensions`
fn iter_files(path: &Path, extensions: Vec<String>) -> impl Iterator<Item = walkdir::DirEntry> {
    let is_hidden = |entry: &walkdir::DirEntry| {
        entry
            .file_name()
            .to_str()
            .map(|s| s.starts_with('.'))
            .unwrap_or(false)
    };

    WalkDir::new(path)
        .into_iter()
        .filter_entry(move |e| !is_hidden(e))
        .filter_map(|e| e.ok())
        .filter(move |entry| {
            if entry.file_type().is_dir() {
                return false;
            }

            let path = entry.path();

            match path.extension() {
                None => return false,
                Some(ext) => {
                    let s = ext.to_str().unwrap_or_default();
                    if !extensions.contains(&s.to_string()) {
                        return false;
                    }
                }
            }
            true
        })
}

pub fn rule_path_seek(rule_path: &Path) -> Vec<Rules> {
    debug!("[+] Rule base directory: {}", rule_path.display());
    let extensions = vec![String::from("yaml")];
    let files: Vec<PathBuf> = iter_files(rule_path, extensions.clone())
        .map(|d| d.into_path())
        .collect();
    let mut rules: Vec<Rules> = vec![];
    for path in files.iter() {
        let data = read_file(path);
        rules.push(parse_yaml(data.as_str()));
    }
    return rules;
}

pub fn read_file(path: &Path) -> String {
    // let c = std::fs::read_to_string(path).unwrap();
    println!("{}", path.display());
    let p = |err: &dyn Error| {
        eprintln!("Error: {}", err);
        return "".to_string();
    };
    match fs::read_to_string(path) {
        Ok(value) => return value.to_string(),
        Err(err) => p(&err),
    }
}

pub fn parse_yaml(data: &str) -> Rules {
    let rules: Rules = serde_yaml::from_str(data).expect("parsing yaml error, check your rule");
    debug!("{}", rules.issue);
    return rules;
}

struct WorkItem {
    qt: QueryTree,
    identifiers: Vec<String>,
    reason: String,
    issue: String,
}

/// Iterate over all paths in `files`, parse files that might contain a match for any of the queries
/// in `work` and send them to the next worker using `sender`.
fn parse_files_worker(
    files: Vec<PathBuf>,
    sender: Sender<(Arc<String>, Tree, String)>,
    work: &[WorkItem],
) {
    let tl = ThreadLocal::new();

    files
        .into_par_iter()
        .for_each_with(sender, move |sender, path| {
            let maybe_parse = |path| {
                let c = match fs::read(path) {
                    Ok(content) => content,
                    Err(_) => return None,
                };

                let source = String::from_utf8_lossy(&c);

                let potential_match = work.iter().any(
                    |WorkItem {
                         qt: _,
                         identifiers,
                         reason: _,
                         issue: _,
                     }| {
                        identifiers.iter().all(|i| source.find(i).is_some())
                    },
                );

                if !potential_match {
                    None
                } else {
                    let mut parser = tl
                        .get_or(|| RefCell::new(weggli_enhance::get_parser()))
                        .borrow_mut();
                    let tree = parser.parse(&source.as_bytes(), None).unwrap();
                    Some((tree, source.to_string()))
                }
            };
            if let Some((source_tree, source)) = maybe_parse(&path) {
                sender
                    .send((Arc::new(source), source_tree, path.display().to_string()))
                    .unwrap();
            }
        });
}

#[derive(Debug)]
struct ResultsCtx {
    query_index: usize,
    path: String,
    source: Arc<String>,
    result: QueryResult,
    reason: String,
    issue: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OutputResults {
    query_index: usize,
    path: String,
    reason: String,
    issue: String,
    start_line: i64,
}



struct Options {
    pub limit: bool,
    pub unique: bool,
}

/// Fetches parsed ASTs from `receiver`, runs all queries in `work` on them and
/// filters the results based on the provided regex `constraints` and --unique --limit switches.
/// For single query runs, the remaining results are directly printed. Otherwise, they get forwarded
/// to `multi_query_worker` through the `results_tx` channel.
fn execute_queries_worker(
    receiver: Receiver<(Arc<String>, Tree, String)>,
    results_tx: Sender<ResultsCtx>,
    work: &[WorkItem],
    options: Options,
) {
    receiver.into_iter().par_bridge().for_each_with(
        results_tx,
        |results_tx, (source, tree, path)| {
            // For each query
            work.iter().enumerate().for_each(
                |(
                    i,
                    WorkItem {
                        qt,
                        identifiers: _,
                        reason,
                        issue,
                    },
                )| {
                    // Run query
                    let matches = qt.matches(tree.root_node(), &source);

                    if matches.is_empty() {
                        return;
                    }

                    // Enforce --unique
                    let check_unique = |m: &QueryResult| {
                        if options.unique {
                            let mut seen = HashSet::new();
                            m.vars
                                .keys()
                                .map(|k| m.value(k, &source).unwrap())
                                .all(|x| seen.insert(x))
                        } else {
                            true
                        }
                    };

                    let mut skip_set = HashSet::new();

                    // Enforce --limit
                    let check_limit = |m: &QueryResult| {
                        if options.limit {
                            skip_set.insert(m.start_offset())
                        } else {
                            true
                        }
                    };

                    // Print match or forward it if we are in a multi query context
                    let process_match = |m: QueryResult| {
                        // single query
                        // if work.len() == 1 {
                        //     let line = source[..m.start_offset()].matches('\n').count() + 1;
                        //     let fmt_reason =
                        //         (" ".to_string() + &reason.clone() + " ").bold().on_blue();
                        //     let fmt_issue =
                        //         (" ".to_string() + &issue.clone() + " ").bold().on_purple();
                        //
                        //     println!("{} : {}", fmt_reason, fmt_issue);
                        //     println!(
                        //         "{}:{}\n{}",
                        //         path.clone().bold(),
                        //         line,
                        //         m.display(
                        //             &source,
                        //             options.before,
                        //             options.after,
                        //             options.enable_line_numbers
                        //         )
                        //     );
                        // } else {
                            results_tx
                                .send(ResultsCtx {
                                    query_index: i,
                                    result: m,
                                    path: path.clone(),
                                    source: source.clone(),
                                    reason: reason.clone(),
                                    issue: issue.clone(),
                                })
                                .unwrap();
                            // println!("{}", log.to_string().bold().on_red());
                        // }
                    };

                    matches
                        .into_iter()
                        .filter(check_unique)
                        .filter(check_limit)
                        .for_each(process_match);
                },
            );
        },
    );
}

/// For multi query runs, we collect all independent results first and filter
/// them to make sure that variable assignments are valid for all queries.
fn results_collector(
    mut results: Vec<ResultsCtx>,
    descriptor: Vec<ReportingDescriptor>,
    enable_sarif: bool,
    sarif_path: Option<PathBuf>,
) {


    // filter results.
    // We now have a list of results for each query in query_results, but we still need to ensure
    // that we only show results for query A that can be combined with at least one result in query B
    // (and C and D).
    // TODO: The runtime of this approach is pretty terrible, think about improving it.
    let filter = |x: &mut ResultsCtx, y: &mut ResultsCtx| {
        x.result.chainable(&x.source, &y.result, &y.source)
    };

    for i in 0..results.len() {
        let (part1, part2) = results.split_at_mut(i + 1);
        let a = part1.last_mut().unwrap();
        for b in part2 {
            filter(a, b);
            filter(b, a);
        }
    }

    let mut final_results = vec![];
    if !enable_sarif {
        // Print remaining results
        let mut counter = 0;
        let mut prints = Vec::new();
        results.into_iter().for_each(|r| {
            let line = r.source[..r.result.start_offset()].matches('\n').count() + 1;
            
            let fmt_reason =
                (" ".to_string() + &r.reason.clone() + " ").bold().on_blue();
            let fmt_issue =
                (" ".to_string() + &r.issue.clone() + " ").bold().on_purple();
            prints.push(format!(
                "{} : {}\n{}:{}\n{}",
                fmt_reason, fmt_issue,
                r.path.bold(),
                line,
                r.result
                    .display(&r.source, 5, 5, true)
            ));
            counter = counter + 1;
        });
        println!("{} {}", counter, "matches".bold().red());
        prints.into_iter().for_each(|x| println!("{}", x));
    } else {
        // output results in SARIF format
        let mut counter = 0;

        //init sarif
        let tool_components = sarif::ToolComponentBuilder::default()
            .name("weggli-enhance")
            .version(env!("CARGO_PKG_VERSION"))
            .rules(descriptor)
            .build()
            .unwrap();
        let tools = sarif::ToolBuilder::default()
            .driver(tool_components)
            .build()
            .unwrap();

        let mut output_results = vec![];

        results.into_iter().for_each(|r| {
            let start_line = r.source[..r.result.start_offset()].matches('\n').count() + 1;
            output_results.push(OutputResults{
                query_index: r.query_index,
                path: r.path,
                reason: r.reason,
                issue: r.issue,
                start_line: start_line as i64,
            });
        });

        let mut unique_results = Vec::new();
        let mut seen = HashSet::new();

        for result in output_results {
            if seen.insert(result.clone()) {
                unique_results.push(result);
            }
        }

        for result in unique_results{
            // let end_line = start_line + 50;

            let sarif_rule = sarif::ReportingDescriptorReferenceBuilder::default()
                .id(result.issue)
                .index(result.query_index as i64)
                .build()
                .unwrap();
            let sarif_message = sarif::MessageBuilder::default()
                .text(result.reason)
                .build()
                .unwrap();
            let sarif_artifact_location = sarif::ArtifactLocationBuilder::default()
                .uri(result.path)
                .build()
                .unwrap();
            let sarif_region = sarif::RegionBuilder::default()
                .start_line(result.start_line)
                .build()
                .unwrap();
            let sarif_physical_location = sarif::PhysicalLocationBuilder::default()
                .artifact_location(sarif_artifact_location)
                .region(sarif_region)
                .build()
                .unwrap();
            let sarif_location = sarif::LocationBuilder::default()
                .physical_location(sarif_physical_location)
                .build()
                .unwrap();
            let sarif_result = sarif::ResultBuilder::default()
                .rule_id(sarif_rule.id.clone().unwrap()).rule_index(sarif_rule.index.clone().unwrap()).rule(sarif_rule)
                .message(sarif_message)
                .locations(vec![sarif_location])
                .build()
                .unwrap();

            // print sarif_result
            final_results.push(sarif_result);
            counter = counter + 1;
        }



        let sarif_struct = sarif::SarifBuilder::default()
            .schema("https://json.schemastore.org/sarif-2.1.0")
            .version("2.1.0")
            .runs(vec![sarif::RunBuilder::default()
                .tool(tools)
                .results(final_results)
                .build()
                .unwrap()])
            .build()
            .unwrap();

        println!("{} {}", counter, "matches".bold().red());
        let sarif_json = serde_json::to_string(&sarif_struct).unwrap();

        // write SARIF to file
        match sarif_path {
            Some(path) => {
                let mut file = File::create(path).unwrap();
                file.write_all(sarif_json.as_bytes()).unwrap();
            }
            None => {}
        }

        // println!("{}", sarif_json);
    }
}

// Exit on SIGPIPE
// see https://github.com/rust-lang/rust/issues/46016#issuecomment-605624865
fn reset_signal_pipe_handler() {
    #[cfg(target_family = "unix")]
    {
        use nix::sys::signal;

        unsafe {
            let _ = signal::signal(signal::Signal::SIGPIPE, signal::SigHandler::SigDfl)
                .map_err(|e| eprintln!("{}", e));
        }
    }
}
