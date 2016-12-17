package android.support.p000a.p001a;

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import org.xmlpull.v1.XmlPullParser;

/* renamed from: android.support.a.a.n */
class C0014n extends C0013q {
    public C0014n(C0014n c0014n) {
        super(c0014n);
    }

    private void m38a(TypedArray typedArray) {
        String string = typedArray.getString(0);
        if (string != null) {
            this.n = string;
        }
        string = typedArray.getString(1);
        if (string != null) {
            this.m = C0006f.m11a(string);
        }
    }

    public void m39a(Resources resources, AttributeSet attributeSet, Theme theme, XmlPullParser xmlPullParser) {
        if (C0010j.m22a(xmlPullParser, "pathData")) {
            TypedArray b = C0001k.m0b(resources, theme, attributeSet, C0000a.f3d);
            m38a(b);
            b.recycle();
        }
    }

    public boolean m40a() {
        return true;
    }
}
