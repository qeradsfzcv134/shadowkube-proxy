all: build save

build:
	cargo build --release --target=x86_64-unknown-linux-musl
save:
	cp target/x86_64-unknown-linux-musl/release/shadow_proxy ./
	rsync -az ./shadow_proxy proxy1:/root/proxy/
	rsync -az ./config.json proxy1:/root/proxy/
	rsync -az ./iptables.sh proxy1:/root/proxy/

