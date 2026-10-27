package dev.onixus.aircrack;

final class NativeBridge {
    static { System.loadLibrary("air_jni"); }
    private NativeBridge() {}
    static native String run(String request);
    // 0 prepare, 1 cancel, 2 read candidate count. One worker per process.
    static native long control(int action);
}
