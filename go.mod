module sialedger

go 1.23.1

toolchain go1.23.6

replace go.sia.tech/core => /home/christopher/prog/go/src/go.sia.tech/core

require (
	github.com/bearsh/hid v1.5.0
	go.sia.tech/core v0.10.2-0.20250211180922-261f960c1315
	lukechampine.com/flagg v1.1.1
)

require (
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	lukechampine.com/frand v1.5.1 // indirect
)
