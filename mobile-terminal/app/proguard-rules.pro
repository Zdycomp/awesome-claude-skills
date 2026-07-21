# Native methods in Pty are resolved by JNI name — keep them unrenamed.
-keepclasseswithmembernames class com.zdycomp.secureterm.term.Pty {
    native <methods>;
}
