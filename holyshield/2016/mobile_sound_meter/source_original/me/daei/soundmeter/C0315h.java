package me.daei.soundmeter;

/* renamed from: me.daei.soundmeter.h */
public class C0315h {
    public static float f1631a;
    private static float f1632b;
    private static float f1633c;
    private static float f1634d;

    static {
        f1631a = 40.0f;
        f1632b = f1631a;
        f1633c = 0.5f;
        f1634d = 0.0f;
    }

    public static void m2880a(float f) {
        if (f > f1632b) {
            f1634d = f - f1632b > f1633c ? f - f1632b : f1633c;
        } else {
            f1634d = f - f1632b < (-f1633c) ? f - f1632b : -f1633c;
        }
        f1631a = f1632b + (f1634d * 0.2f);
        f1632b = f1631a;
    }
}
