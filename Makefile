# Makefile - convenience targets for nfs-utils-rs
#
# 20261125 - Created by Claude (claude.ai, Anthropic) - scottfk

REFERENCE ?= ../nfs-utils

.PHONY: all reference check clippy fmt clean

all:
	cargo build --release

reference:
	tools/build-reference.sh $(REFERENCE)

check:
	@test -x $(REFERENCE)/utils/statd/statd || tools/build-reference.sh $(REFERENCE)
	NFSUTILS_REFERENCE=$(abspath $(REFERENCE)) cargo test --release

clippy:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean
