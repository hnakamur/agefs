module github.com/hnakamur/agefs

go 1.19

require (
	filippo.io/age v1.0.0
	github.com/go-git/go-git/v5 v5.4.2
	github.com/hanwen/go-fuse/v2 v2.1.0
	github.com/hnakamur/ageutil v0.0.1
	golang.org/x/sys v0.0.0-20210903071746-97244b99971b
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1 // indirect
	github.com/acomagu/bufpipe v1.0.3 // indirect
	github.com/go-git/gcfg v1.5.0 // indirect
	github.com/go-git/go-billy/v5 v5.3.1 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/crypto v0.0.0-20221010152910-d6f0a8c073c2 // indirect
	golang.org/x/net v0.0.0-20211112202133-69e39bad7dc2 // indirect
	golang.org/x/term v0.0.0-20220919170432-7a66f970e087 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)

replace github.com/hnakamur/ageutil => ../ageutil
