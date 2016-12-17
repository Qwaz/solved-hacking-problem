package android.support.p000a.p001a;

import android.content.res.TypedArray;
import org.xmlpull.v1.XmlPullParser;

/* renamed from: android.support.a.a.j */
class C0010j {
    public static float m19a(TypedArray typedArray, XmlPullParser xmlPullParser, String str, int i, float f) {
        return !C0010j.m22a(xmlPullParser, str) ? f : typedArray.getFloat(i, f);
    }

    public static int m20a(TypedArray typedArray, XmlPullParser xmlPullParser, String str, int i, int i2) {
        return !C0010j.m22a(xmlPullParser, str) ? i2 : typedArray.getInt(i, i2);
    }

    public static boolean m21a(TypedArray typedArray, XmlPullParser xmlPullParser, String str, int i, boolean z) {
        return !C0010j.m22a(xmlPullParser, str) ? z : typedArray.getBoolean(i, z);
    }

    public static boolean m22a(XmlPullParser xmlPullParser, String str) {
        return xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", str) != null;
    }

    public static int m23b(TypedArray typedArray, XmlPullParser xmlPullParser, String str, int i, int i2) {
        return !C0010j.m22a(xmlPullParser, str) ? i2 : typedArray.getColor(i, i2);
    }
}
