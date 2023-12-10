#### Before you read
- **Wrapper** *// code that uses XRay-core as a framework, build on top of it*
- **Callbacks** *// function that are specified by wrappers and executed by XRay when something happens. Can be used by wrappers to collect statistics and many more*   

## Changes plan
### Add inbound callbacks
**Status**: In process of research which callbacks to create and where to call them.  
The idea of callbacks is that you can get any data, any event you need from inbounds/outbounds. For example; new user created, new request to inbound happend, or anything else => your function called and event's data is probided in arguments. In the original Xray inbounds depend on statistics, they're creating counters for it, they're changing it, and IMO that's the bad architecture solution. Statistics should depend on inbounds and collect needed data by itself and callbacks will make it possible, also allowing to implement any statistics inside the wrapper, making that approach more flexible. And it's possible that callbacks usage will go beyond just statistics, for example: logging events information. 


### Make more public values or getters/setters
**Status**: In process.  
Original XRay-core code has a lot of private values in the structures. I want to change it to avoid the unsafe code in wrappers and add flexibility to the codebase. All the changes will be concurrent safe.


### Remove default statistics
**Status**: Task frozen.  
Will start to work on it when callbacks are fully implemented and tested


### Configuration from code problem
**Status**: Task frozen.  
Configuration in JSON, for example, is already validated on build stage and if you have wrong key length or something like this -- you will get an error. But if you are trying to config XRay from code -- you most likely gonna debug a lot, just because you're passing the wrong values into the config. Also, configuration in Documentation for JSON has a little differences to a code configuration what makes problem even worse. [Example of the problem in real-world situation](https://github.com/XTLS/Xray-core/issues/2728)

There are two possible solution to this problem:
- Configuration validator. Before put configuration to initialize the Instance it will go through all the values.
- Make constructors validate config.


### Remove protobuf configuration and just use structures for configurations
**Status**: Frozen + waiting for responses in [discussion XRay](https://github.com/XTLS/Xray-core/discussions/2789) and [discussion V2Ray](https://github.com/v2fly/v2ray-core/discussions/2802)  
All in all I don't see any reason to use protobuf for configuration. IMO it overcomplicate things and overall don't make much good impact.

UPD: Seems to be really time-consuming task with big amount of work, so moved to the end of plan.