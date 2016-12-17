package me.daei.soundmeter;

/* renamed from: me.daei.soundmeter.h */
public class StaticHolder {
    public static float now;
    private static float current;
    private static float maxDelta;
    private static float delta;

    static {
        now = 40.0f;
        current = now;
        maxDelta = 0.5f;
        delta = 0.0f;
    }

    public static void update(float f) {
        if (f > current) {
            delta = f - current > maxDelta ? f - current : maxDelta;
        } else {
            delta = f - current < (-maxDelta) ? f - current : -maxDelta;
        }
        now = current + (delta * 0.2f);
        current = now;
    }
}
