# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Lafeng/deblocus](https://github.com/Lafeng/deblocus).

## 0.12.3520-beta 15/12/18
bug fixes;
build on go1.5.2;

## 0.12.2970-beta 15/10/24
implement high-performance encryption;
implement verifying packet header checksum;
implement support for aarch64(armv8);
and some improvements;

## 0.11.2810-beta 15/10/4
improve compatibility of literal ipv6 address;
improve security by update iv generation;

## 0.11.2770-beta 15/10/4
improve the security of d5 protocol;
add chacha encryption implementation;
and bug fixes;

## 0.10.2640-beta 15/9/20
fix incorrect geo switch

## 0.10.2630-beta 15/9/20
implement filtering dest network
improve on multiplexer spec
change some configuration options

## 0.9.2520-beta 15/9/9
update initial cipher and nextsid method
- update cipher to use empty one during initialization
- next_sid update to atomic operation

## 0.9.2500-beta 15/9/7
fix http tunnel handshaking error that was caused by a redundant LF in version string
update rest interval in sema test

## 0.9.2470-beta 15/9/4
fix some potential issues of data race
- update to atomic opearations of edgeConn.closed
- update multiplexer test and fix endless io waiting if lost
- update semaphore excluding race test

## 0.9.2460-beta 15/9/3
enable tcp keepalive

## 0.9.2451-beta 15/9/2
add cwd for detecting config

## 0.9.2450-beta 15/9/2
fix missing identifier of tunnel, that will caused incorret socket not found error.

## 0.9.2420-beta 15/8/28
implement and improve fast-open feature

## 0.9.2390-beta 15/8/25
update tunnel structure
- merge signalTunnel into dataTun
- remove signalTunnel and related
- enhance managing client state of session
- enable server pool for selecting

## [0.9.2230-beta] 15/8/11
- fixed improper local close when remote open failed

## [0.9.2220-beta] 15/8/10
- refactored mux and improved performance

## [0.9.2170-beta] 15/8/5
- implement http proxy basically

## [0.8.X-beta]
- implement tcp multiplexer on tunnel
- improve log output
- improve reconnect logic and error handling in multiplexer and pool
- update handshaking
- clean up and refactor

## [0.6.0593-alpha] - 2015-2-28
### Fixed
- Fix glog test
- Fix process of ver arg. add identifier in ping log.

### Removed
- Remove arg-listen. fix output file processing when use arg-output.

## [0.6.0412-alpha] - 2015-2-10
### Added
- Update command packet
- Update dyna iv

## [0.6.0352-alpha] - 2015-2-4
### Added 
- Small modify; 


## [0.6.0351-alpha] - 2015-2-4
### Added
- Update d5 nego
-	Improve heartbeat

## [0.5.0291-alpha] - 2015-1-29
### Fixed
- Update verbose setting;
- Fix token req excess. improve ctltun keepalive..

## [0.5.0200-alpha] - 2015-1-23
### Fixed
- Fix ex catch, fix multiple backend

### Added
- Update verbose setting

## [0.5.0130-alpha] - 2015-1-13
### Added
- Add version

### Fixed
- Fix retrying
- Fix disconn retry
- Fix token waiting

...
## 0.5.0 - 2015-1-8
### Init
- Init
