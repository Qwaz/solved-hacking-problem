package android.support.p000a.p001a;

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.Paint.Cap;
import android.graphics.Paint.Join;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import org.xmlpull.v1.XmlPullParser;

/* renamed from: android.support.a.a.o */
class C0015o extends C0013q {
    int f34a;
    float f35b;
    int f36c;
    float f37d;
    int f38e;
    float f39f;
    float f40g;
    float f41h;
    float f42i;
    Cap f43j;
    Join f44k;
    float f45l;
    private int[] f46p;

    public C0015o() {
        this.f34a = 0;
        this.f35b = 0.0f;
        this.f36c = 0;
        this.f37d = 1.0f;
        this.f39f = 1.0f;
        this.f40g = 0.0f;
        this.f41h = 1.0f;
        this.f42i = 0.0f;
        this.f43j = Cap.BUTT;
        this.f44k = Join.MITER;
        this.f45l = 4.0f;
    }

    public C0015o(C0015o c0015o) {
        super(c0015o);
        this.f34a = 0;
        this.f35b = 0.0f;
        this.f36c = 0;
        this.f37d = 1.0f;
        this.f39f = 1.0f;
        this.f40g = 0.0f;
        this.f41h = 1.0f;
        this.f42i = 0.0f;
        this.f43j = Cap.BUTT;
        this.f44k = Join.MITER;
        this.f45l = 4.0f;
        this.f46p = c0015o.f46p;
        this.f34a = c0015o.f34a;
        this.f35b = c0015o.f35b;
        this.f37d = c0015o.f37d;
        this.f36c = c0015o.f36c;
        this.f38e = c0015o.f38e;
        this.f39f = c0015o.f39f;
        this.f40g = c0015o.f40g;
        this.f41h = c0015o.f41h;
        this.f42i = c0015o.f42i;
        this.f43j = c0015o.f43j;
        this.f44k = c0015o.f44k;
        this.f45l = c0015o.f45l;
    }

    private Cap m41a(int i, Cap cap) {
        switch (i) {
            case C0243l.View_android_theme /*0*/:
                return Cap.BUTT;
            case C0243l.View_android_focusable /*1*/:
                return Cap.ROUND;
            case C0243l.View_paddingStart /*2*/:
                return Cap.SQUARE;
            default:
                return cap;
        }
    }

    private Join m42a(int i, Join join) {
        switch (i) {
            case C0243l.View_android_theme /*0*/:
                return Join.MITER;
            case C0243l.View_android_focusable /*1*/:
                return Join.ROUND;
            case C0243l.View_paddingStart /*2*/:
                return Join.BEVEL;
            default:
                return join;
        }
    }

    private void m43a(TypedArray typedArray, XmlPullParser xmlPullParser) {
        this.f46p = null;
        if (C0010j.m22a(xmlPullParser, "pathData")) {
            String string = typedArray.getString(0);
            if (string != null) {
                this.n = string;
            }
            string = typedArray.getString(2);
            if (string != null) {
                this.m = C0006f.m11a(string);
            }
            this.f36c = C0010j.m23b(typedArray, xmlPullParser, "fillColor", 1, this.f36c);
            this.f39f = C0010j.m19a(typedArray, xmlPullParser, "fillAlpha", 12, this.f39f);
            this.f43j = m41a(C0010j.m20a(typedArray, xmlPullParser, "strokeLineCap", 8, -1), this.f43j);
            this.f44k = m42a(C0010j.m20a(typedArray, xmlPullParser, "strokeLineJoin", 9, -1), this.f44k);
            this.f45l = C0010j.m19a(typedArray, xmlPullParser, "strokeMiterLimit", 10, this.f45l);
            this.f34a = C0010j.m23b(typedArray, xmlPullParser, "strokeColor", 3, this.f34a);
            this.f37d = C0010j.m19a(typedArray, xmlPullParser, "strokeAlpha", 11, this.f37d);
            this.f35b = C0010j.m19a(typedArray, xmlPullParser, "strokeWidth", 4, this.f35b);
            this.f41h = C0010j.m19a(typedArray, xmlPullParser, "trimPathEnd", 6, this.f41h);
            this.f42i = C0010j.m19a(typedArray, xmlPullParser, "trimPathOffset", 7, this.f42i);
            this.f40g = C0010j.m19a(typedArray, xmlPullParser, "trimPathStart", 5, this.f40g);
        }
    }

    public void m44a(Resources resources, AttributeSet attributeSet, Theme theme, XmlPullParser xmlPullParser) {
        TypedArray b = C0001k.m0b(resources, theme, attributeSet, C0000a.f2c);
        m43a(b, xmlPullParser);
        b.recycle();
    }
}
