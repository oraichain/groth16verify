rustup target install i686-pc-windows-msvc
cargo build --target=i686-pc-windows-msvc --release
copy target\i686-pc-windows-msvc\release\zwaves_jni.dll javalib\src\main\resources\META-INF\native\windows32

rustup target install x86_64-pc-windows-msvc
cargo build --target=x86_64-pc-windows-msvc --release
copy target\x86_64-pc-windows-msvc\release\zwaves_jni.dll javalib\src\main\resources\META-INF\native\windows64

