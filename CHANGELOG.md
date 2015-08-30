# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [spance/deblocus](https://github.com/spance/deblocus).

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

## [0.6.0593-alpha](https://github.com/spance/deblocus/compare/0.6.0412-alpha...0.6.0593-alpha) - 2015-2-28
### Fixed
- Fix glog test
- Fix process of ver arg. add identifier in ping log.

### Removed
- Remove arg-listen. fix output file processing when use arg-output.

## [0.6.0412-alpha](https://github.com/spance/deblocus/compare/0.6.0352-alpha...0.6.0412-alpha) - 2015-2-10
### Added
- Update command packet
- Update dyna iv

## [0.6.0352-alpha](https://github.com/spance/deblocus/compare/0.6.0351-alpha...0.6.0352-alpha) - 2015-2-4
### Added 
- Small modify; 


## [0.6.0351-alpha](https://github.com/spance/deblocus/compare/0.5.0291-alpha...0.6.0351-alpha) - 2015-2-4
### Added
- Update d5 nego
-	Improve heartbeat

## [0.5.0291-alpha](https://github.com/spance/deblocus/compare/0.5.0200-alpha...0.5.0291-alpha) - 2015-1-29
### Fixed
- Update verbose setting;
- Fix token req excess. improve ctltun keepalive..

## [0.5.0200-alpha](https://github.com/spance/deblocus/compare/0.5.0130-alpha...0.5.0200-alpha) - 2015-1-23
### Fixed
- Fix ex catch, fix multiple backend

### Added
- Update verbose setting

## [0.5.0130-alpha](https://github.com/spance/deblocus/compare/0.5.0...0.5.0130-alpha) - 2015-1-13
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
