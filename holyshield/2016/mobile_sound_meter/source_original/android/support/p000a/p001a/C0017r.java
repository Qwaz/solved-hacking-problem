package android.support.p000a.p001a;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Paint.Style;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.graphics.Region.Op;
import android.support.v4.p012g.C0107a;

/* renamed from: android.support.a.a.r */
class C0017r {
    private static final Matrix f60j;
    float f61a;
    float f62b;
    float f63c;
    float f64d;
    int f65e;
    String f66f;
    final C0107a f67g;
    private final Path f68h;
    private final Path f69i;
    private final Matrix f70k;
    private Paint f71l;
    private Paint f72m;
    private PathMeasure f73n;
    private int f74o;
    private final C0016p f75p;

    static {
        f60j = new Matrix();
    }

    public C0017r() {
        this.f70k = new Matrix();
        this.f61a = 0.0f;
        this.f62b = 0.0f;
        this.f63c = 0.0f;
        this.f64d = 0.0f;
        this.f65e = 255;
        this.f66f = null;
        this.f67g = new C0107a();
        this.f75p = new C0016p();
        this.f68h = new Path();
        this.f69i = new Path();
    }

    public C0017r(C0017r c0017r) {
        this.f70k = new Matrix();
        this.f61a = 0.0f;
        this.f62b = 0.0f;
        this.f63c = 0.0f;
        this.f64d = 0.0f;
        this.f65e = 255;
        this.f66f = null;
        this.f67g = new C0107a();
        this.f75p = new C0016p(c0017r.f75p, this.f67g);
        this.f68h = new Path(c0017r.f68h);
        this.f69i = new Path(c0017r.f69i);
        this.f61a = c0017r.f61a;
        this.f62b = c0017r.f62b;
        this.f63c = c0017r.f63c;
        this.f64d = c0017r.f64d;
        this.f74o = c0017r.f74o;
        this.f65e = c0017r.f65e;
        this.f66f = c0017r.f66f;
        if (c0017r.f66f != null) {
            this.f67g.put(c0017r.f66f, this);
        }
    }

    private static float m52a(float f, float f2, float f3, float f4) {
        return (f * f4) - (f2 * f3);
    }

    private float m53a(Matrix matrix) {
        float[] fArr = new float[]{0.0f, 1.0f, 1.0f, 0.0f};
        matrix.mapVectors(fArr);
        float hypot = (float) Math.hypot((double) fArr[0], (double) fArr[1]);
        float hypot2 = (float) Math.hypot((double) fArr[2], (double) fArr[3]);
        float a = C0017r.m52a(fArr[0], fArr[1], fArr[2], fArr[3]);
        hypot = Math.max(hypot, hypot2);
        return hypot > 0.0f ? Math.abs(a) / hypot : 0.0f;
    }

    private void m56a(C0016p c0016p, Matrix matrix, Canvas canvas, int i, int i2, ColorFilter colorFilter) {
        c0016p.f48b.set(matrix);
        c0016p.f48b.preConcat(c0016p.f56j);
        for (int i3 = 0; i3 < c0016p.f47a.size(); i3++) {
            Object obj = c0016p.f47a.get(i3);
            if (obj instanceof C0016p) {
                m56a((C0016p) obj, c0016p.f48b, canvas, i, i2, colorFilter);
            } else if (obj instanceof C0013q) {
                m57a(c0016p, (C0013q) obj, canvas, i, i2, colorFilter);
            }
        }
    }

    private void m57a(C0016p c0016p, C0013q c0013q, Canvas canvas, int i, int i2, ColorFilter colorFilter) {
        float f = ((float) i) / this.f63c;
        float f2 = ((float) i2) / this.f64d;
        float min = Math.min(f, f2);
        Matrix b = c0016p.f48b;
        this.f70k.set(b);
        this.f70k.postScale(f, f2);
        f = m53a(b);
        if (f != 0.0f) {
            c0013q.m35a(this.f68h);
            Path path = this.f68h;
            this.f69i.reset();
            if (c0013q.m36a()) {
                this.f69i.addPath(path, this.f70k);
                canvas.clipPath(this.f69i, Op.REPLACE);
                return;
            }
            Paint paint;
            C0015o c0015o = (C0015o) c0013q;
            if (!(c0015o.f40g == 0.0f && c0015o.f41h == 1.0f)) {
                float f3 = (c0015o.f40g + c0015o.f42i) % 1.0f;
                float f4 = (c0015o.f41h + c0015o.f42i) % 1.0f;
                if (this.f73n == null) {
                    this.f73n = new PathMeasure();
                }
                this.f73n.setPath(this.f68h, false);
                float length = this.f73n.getLength();
                f3 *= length;
                f4 *= length;
                path.reset();
                if (f3 > f4) {
                    this.f73n.getSegment(f3, length, path, true);
                    this.f73n.getSegment(0.0f, f4, path, true);
                } else {
                    this.f73n.getSegment(f3, f4, path, true);
                }
                path.rLineTo(0.0f, 0.0f);
            }
            this.f69i.addPath(path, this.f70k);
            if (c0015o.f36c != 0) {
                if (this.f72m == null) {
                    this.f72m = new Paint();
                    this.f72m.setStyle(Style.FILL);
                    this.f72m.setAntiAlias(true);
                }
                paint = this.f72m;
                paint.setColor(C0011l.m30b(c0015o.f36c, c0015o.f39f));
                paint.setColorFilter(colorFilter);
                canvas.drawPath(this.f69i, paint);
            }
            if (c0015o.f34a != 0) {
                if (this.f71l == null) {
                    this.f71l = new Paint();
                    this.f71l.setStyle(Style.STROKE);
                    this.f71l.setAntiAlias(true);
                }
                paint = this.f71l;
                if (c0015o.f44k != null) {
                    paint.setStrokeJoin(c0015o.f44k);
                }
                if (c0015o.f43j != null) {
                    paint.setStrokeCap(c0015o.f43j);
                }
                paint.setStrokeMiter(c0015o.f45l);
                paint.setColor(C0011l.m30b(c0015o.f34a, c0015o.f37d));
                paint.setColorFilter(colorFilter);
                paint.setStrokeWidth((f * min) * c0015o.f35b);
                canvas.drawPath(this.f69i, paint);
            }
        }
    }

    public int m61a() {
        return this.f65e;
    }

    public void m62a(float f) {
        m63a((int) (255.0f * f));
    }

    public void m63a(int i) {
        this.f65e = i;
    }

    public void m64a(Canvas canvas, int i, int i2, ColorFilter colorFilter) {
        m56a(this.f75p, f60j, canvas, i, i2, colorFilter);
    }

    public float m65b() {
        return ((float) m61a()) / 255.0f;
    }
}
