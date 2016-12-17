package android.support.p000a.p001a;

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.Matrix;
import android.support.v4.p012g.C0107a;
import android.util.AttributeSet;
import java.util.ArrayList;
import org.xmlpull.v1.XmlPullParser;

/* renamed from: android.support.a.a.p */
class C0016p {
    final ArrayList f47a;
    private final Matrix f48b;
    private float f49c;
    private float f50d;
    private float f51e;
    private float f52f;
    private float f53g;
    private float f54h;
    private float f55i;
    private final Matrix f56j;
    private int f57k;
    private int[] f58l;
    private String f59m;

    public C0016p() {
        this.f48b = new Matrix();
        this.f47a = new ArrayList();
        this.f49c = 0.0f;
        this.f50d = 0.0f;
        this.f51e = 0.0f;
        this.f52f = 1.0f;
        this.f53g = 1.0f;
        this.f54h = 0.0f;
        this.f55i = 0.0f;
        this.f56j = new Matrix();
        this.f59m = null;
    }

    public C0016p(C0016p c0016p, C0107a c0107a) {
        this.f48b = new Matrix();
        this.f47a = new ArrayList();
        this.f49c = 0.0f;
        this.f50d = 0.0f;
        this.f51e = 0.0f;
        this.f52f = 1.0f;
        this.f53g = 1.0f;
        this.f54h = 0.0f;
        this.f55i = 0.0f;
        this.f56j = new Matrix();
        this.f59m = null;
        this.f49c = c0016p.f49c;
        this.f50d = c0016p.f50d;
        this.f51e = c0016p.f51e;
        this.f52f = c0016p.f52f;
        this.f53g = c0016p.f53g;
        this.f54h = c0016p.f54h;
        this.f55i = c0016p.f55i;
        this.f58l = c0016p.f58l;
        this.f59m = c0016p.f59m;
        this.f57k = c0016p.f57k;
        if (this.f59m != null) {
            c0107a.put(this.f59m, this);
        }
        this.f56j.set(c0016p.f56j);
        ArrayList arrayList = c0016p.f47a;
        for (int i = 0; i < arrayList.size(); i++) {
            Object obj = arrayList.get(i);
            if (obj instanceof C0016p) {
                this.f47a.add(new C0016p((C0016p) obj, c0107a));
            } else {
                C0013q c0015o;
                if (obj instanceof C0015o) {
                    c0015o = new C0015o((C0015o) obj);
                } else if (obj instanceof C0014n) {
                    c0015o = new C0014n((C0014n) obj);
                } else {
                    throw new IllegalStateException("Unknown object in the tree!");
                }
                this.f47a.add(c0015o);
                if (c0015o.f32n != null) {
                    c0107a.put(c0015o.f32n, c0015o);
                }
            }
        }
    }

    private void m46a(TypedArray typedArray, XmlPullParser xmlPullParser) {
        this.f58l = null;
        this.f49c = C0010j.m19a(typedArray, xmlPullParser, "rotation", 5, this.f49c);
        this.f50d = typedArray.getFloat(1, this.f50d);
        this.f51e = typedArray.getFloat(2, this.f51e);
        this.f52f = C0010j.m19a(typedArray, xmlPullParser, "scaleX", 3, this.f52f);
        this.f53g = C0010j.m19a(typedArray, xmlPullParser, "scaleY", 4, this.f53g);
        this.f54h = C0010j.m19a(typedArray, xmlPullParser, "translateX", 6, this.f54h);
        this.f55i = C0010j.m19a(typedArray, xmlPullParser, "translateY", 7, this.f55i);
        String string = typedArray.getString(0);
        if (string != null) {
            this.f59m = string;
        }
        m48b();
    }

    private void m48b() {
        this.f56j.reset();
        this.f56j.postTranslate(-this.f50d, -this.f51e);
        this.f56j.postScale(this.f52f, this.f53g);
        this.f56j.postRotate(this.f49c, 0.0f, 0.0f);
        this.f56j.postTranslate(this.f54h + this.f50d, this.f55i + this.f51e);
    }

    public String m50a() {
        return this.f59m;
    }

    public void m51a(Resources resources, AttributeSet attributeSet, Theme theme, XmlPullParser xmlPullParser) {
        TypedArray b = C0001k.m0b(resources, theme, attributeSet, C0000a.f1b);
        m46a(b, xmlPullParser);
        b.recycle();
    }
}
