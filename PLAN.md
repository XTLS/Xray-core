#### Before you read
- **Wrapper** *// code that uses XRay-core as a framework, build on top of it*
- **Callbacks** *// function that are specified by wrappers and executed by XRay when something happens (for example, new user created, or new request to inbound happend). Can be used by wrappers to collect statistics and many more*   

## Changes plan
### Add inbound callbacks
**Status**: In process of research which callbacks to create and where to call them

The idea of callbacks is that you can get any data, any event you need from inbounds/outbounds. In the original Xray inbounds are depend on statistics, they're creating counters for it, they're changing it, and IMO that's the bad architecture solution. Statistics should depend on inbounds and collect needed data by themselfs and callbacks will make it possible, also allowing to implement any statistics inside the wrapper, making that approach more flexible and extendable by the user. And it's possible that callbacks usage will go beyond just statistics. 

### Make more public values and getters/setters
**Status**: In process
Original XRay-core code has a lot of private values in the structures. I want to change it to avoid the unsafe code in wrappers and add flexibility to the codebase. All the changes will be concurrent safe

### Removing the default statistics
**Status**: Task frozen
Will start to work on it when callbacks are fully implemented and tested

### Remove protobuf configuration and just use structures for configurations
**Status**: waiting for responses in [discussion XRay]() and [discussion V2Ray]()

All in all I don't see any reason to use protobuf for configuration. IMO it overcomplicate things and overall don't make much good impact.