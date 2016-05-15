# mbedtlscpp

Simple C++ wrappers around the mbed tls library (https://tls.mbed.org/). Currently very much in beta - I'm just wrapping functions as I need them so there are quite a lot of gaps.

The aim is to provide only simple wrappings rather than a full C++ framework. The mbed tls structs are wrapped as objects so that they can be used with RAII type code, and functions operating on them added as methods to the corresponding class. Here and there I've added a convenience function to set sensible defaults.

The licence is Apache 2.0 (I don't really care but it's probably easier to inherit the mbed licence).
