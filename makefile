WINDOWS_TARGET=x86_64-pc-windows-gnu
LINUX_TARGET=x86_64-unknown-linux-musl

all: windows linux

linux:
	cargo build --target $(LINUX_TARGET) --release
	upx --best --lzma target/x86_64-unknown-linux-musl/release/weggli-enhance
	cp target/x86_64-unknown-linux-musl/release/weggli-enhance .

windows:
	cargo build --target $(WINDOWS_TARGET) --release
	upx --best --lzma target/x86_64-pc-windows-gnu/release/weggli-enhance.exe
	cp target/x86_64-pc-windows-gnu/release/weggli-enhance.exe .

clean:
	cargo clean
	rm weggli-enhance weggli-enhance.exe