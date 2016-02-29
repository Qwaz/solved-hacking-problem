package android.support.v4.widget;

import android.support.v4.view.C0050m;
import android.support.v4.view.C0056s;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import java.util.Arrays;

/* renamed from: android.support.v4.widget.y */
public class C0086y {
    private static final Interpolator f333v;
    private int f334a;
    private int f335b;
    private int f336c;
    private float[] f337d;
    private float[] f338e;
    private float[] f339f;
    private float[] f340g;
    private int[] f341h;
    private int[] f342i;
    private int[] f343j;
    private int f344k;
    private VelocityTracker f345l;
    private float f346m;
    private float f347n;
    private int f348o;
    private int f349p;
    private C0071j f350q;
    private final aa f351r;
    private View f352s;
    private boolean f353t;
    private final ViewGroup f354u;
    private final Runnable f355w;

    static {
        f333v = new C0087z();
    }

    private float m538a(float f) {
        return (float) Math.sin((double) ((float) (((double) (f - 0.5f)) * 0.4712389167638204d)));
    }

    private float m539a(float f, float f2, float f3) {
        float abs = Math.abs(f);
        return abs < f2 ? 0.0f : abs > f3 ? f <= 0.0f ? -f3 : f3 : f;
    }

    private int m540a(int i, int i2, int i3) {
        if (i == 0) {
            return 0;
        }
        int width = this.f354u.getWidth();
        int i4 = width / 2;
        float a = (m538a(Math.min(1.0f, ((float) Math.abs(i)) / ((float) width))) * ((float) i4)) + ((float) i4);
        i4 = Math.abs(i2);
        return Math.min(i4 > 0 ? Math.round(Math.abs(a / ((float) i4)) * 1000.0f) * 4 : (int) (((((float) Math.abs(i)) / ((float) i3)) + 1.0f) * 256.0f), 600);
    }

    private int m541a(View view, int i, int i2, int i3, int i4) {
        int b = m547b(i3, (int) this.f347n, (int) this.f346m);
        int b2 = m547b(i4, (int) this.f347n, (int) this.f346m);
        int abs = Math.abs(i);
        int abs2 = Math.abs(i2);
        int abs3 = Math.abs(b);
        int abs4 = Math.abs(b2);
        int i5 = abs3 + abs4;
        int i6 = abs + abs2;
        return (int) (((b2 != 0 ? ((float) abs4) / ((float) i5) : ((float) abs2) / ((float) i6)) * ((float) m540a(i2, b2, this.f351r.m441b(view)))) + ((b != 0 ? ((float) abs3) / ((float) i5) : ((float) abs) / ((float) i6)) * ((float) m540a(i, b, this.f351r.m434a(view)))));
    }

    private void m542a(float f, float f2) {
        this.f353t = true;
        this.f351r.m438a(this.f352s, f, f2);
        this.f353t = false;
        if (this.f334a == 1) {
            m564b(0);
        }
    }

    private void m543a(float f, float f2, int i) {
        m553e(i);
        float[] fArr = this.f337d;
        this.f339f[i] = f;
        fArr[i] = f;
        fArr = this.f338e;
        this.f340g[i] = f2;
        fArr[i] = f2;
        this.f341h[i] = m552e((int) f, (int) f2);
        this.f344k |= 1 << i;
    }

    private boolean m544a(float f, float f2, int i, int i2) {
        float abs = Math.abs(f);
        float abs2 = Math.abs(f2);
        if ((this.f341h[i] & i2) != i2 || (this.f349p & i2) == 0 || (this.f343j[i] & i2) == i2 || (this.f342i[i] & i2) == i2) {
            return false;
        }
        if (abs <= ((float) this.f335b) && abs2 <= ((float) this.f335b)) {
            return false;
        }
        if (abs >= abs2 * 0.5f || !this.f351r.m445b(i2)) {
            return (this.f342i[i] & i2) == 0 && abs > ((float) this.f335b);
        } else {
            int[] iArr = this.f343j;
            iArr[i] = iArr[i] | i2;
            return false;
        }
    }

    private boolean m545a(int i, int i2, int i3, int i4) {
        int left = this.f352s.getLeft();
        int top = this.f352s.getTop();
        int i5 = i - left;
        int i6 = i2 - top;
        if (i5 == 0 && i6 == 0) {
            this.f350q.m499g();
            m564b(0);
            return false;
        }
        this.f350q.m492a(left, top, i5, i6, m541a(this.f352s, i5, i6, i3, i4));
        m564b(2);
        return true;
    }

    private boolean m546a(View view, float f, float f2) {
        if (view == null) {
            return false;
        }
        boolean z = this.f351r.m434a(view) > 0;
        boolean z2 = this.f351r.m441b(view) > 0;
        return (z && z2) ? (f * f) + (f2 * f2) > ((float) (this.f335b * this.f335b)) : z ? Math.abs(f) > ((float) this.f335b) : z2 ? Math.abs(f2) > ((float) this.f335b) : false;
    }

    private int m547b(int i, int i2, int i3) {
        int abs = Math.abs(i);
        return abs < i2 ? 0 : abs > i3 ? i <= 0 ? -i3 : i3 : i;
    }

    private void m548b(float f, float f2, int i) {
        int i2 = 1;
        if (!m544a(f, f2, i, 1)) {
            i2 = 0;
        }
        if (m544a(f2, f, i, 4)) {
            i2 |= 4;
        }
        if (m544a(f, f2, i, 2)) {
            i2 |= 2;
        }
        if (m544a(f2, f, i, 8)) {
            i2 |= 8;
        }
        if (i2 != 0) {
            int[] iArr = this.f342i;
            iArr[i] = iArr[i] | i2;
            this.f351r.m443b(i2, i);
        }
    }

    private void m549b(int i, int i2, int i3, int i4) {
        int a;
        int b;
        int left = this.f352s.getLeft();
        int top = this.f352s.getTop();
        if (i3 != 0) {
            a = this.f351r.m435a(this.f352s, i, i3);
            this.f352s.offsetLeftAndRight(a - left);
        } else {
            a = i;
        }
        if (i4 != 0) {
            b = this.f351r.m442b(this.f352s, i2, i4);
            this.f352s.offsetTopAndBottom(b - top);
        } else {
            b = i2;
        }
        if (i3 != 0 || i4 != 0) {
            this.f351r.m439a(this.f352s, a, b, a - left, b - top);
        }
    }

    private void m550c(MotionEvent motionEvent) {
        int c = C0050m.m329c(motionEvent);
        for (int i = 0; i < c; i++) {
            int b = C0050m.m327b(motionEvent, i);
            float c2 = C0050m.m328c(motionEvent, i);
            float d = C0050m.m330d(motionEvent, i);
            this.f339f[b] = c2;
            this.f340g[b] = d;
        }
    }

    private void m551d(int i) {
        if (this.f337d != null) {
            this.f337d[i] = 0.0f;
            this.f338e[i] = 0.0f;
            this.f339f[i] = 0.0f;
            this.f340g[i] = 0.0f;
            this.f341h[i] = 0;
            this.f342i[i] = 0;
            this.f343j[i] = 0;
            this.f344k &= (1 << i) ^ -1;
        }
    }

    private int m552e(int i, int i2) {
        int i3 = 0;
        if (i < this.f354u.getLeft() + this.f348o) {
            i3 = 1;
        }
        if (i2 < this.f354u.getTop() + this.f348o) {
            i3 |= 4;
        }
        if (i > this.f354u.getRight() - this.f348o) {
            i3 |= 2;
        }
        return i2 > this.f354u.getBottom() - this.f348o ? i3 | 8 : i3;
    }

    private void m553e(int i) {
        if (this.f337d == null || this.f337d.length <= i) {
            Object obj = new float[(i + 1)];
            Object obj2 = new float[(i + 1)];
            Object obj3 = new float[(i + 1)];
            Object obj4 = new float[(i + 1)];
            Object obj5 = new int[(i + 1)];
            Object obj6 = new int[(i + 1)];
            Object obj7 = new int[(i + 1)];
            if (this.f337d != null) {
                System.arraycopy(this.f337d, 0, obj, 0, this.f337d.length);
                System.arraycopy(this.f338e, 0, obj2, 0, this.f338e.length);
                System.arraycopy(this.f339f, 0, obj3, 0, this.f339f.length);
                System.arraycopy(this.f340g, 0, obj4, 0, this.f340g.length);
                System.arraycopy(this.f341h, 0, obj5, 0, this.f341h.length);
                System.arraycopy(this.f342i, 0, obj6, 0, this.f342i.length);
                System.arraycopy(this.f343j, 0, obj7, 0, this.f343j.length);
            }
            this.f337d = obj;
            this.f338e = obj2;
            this.f339f = obj3;
            this.f340g = obj4;
            this.f341h = obj5;
            this.f342i = obj6;
            this.f343j = obj7;
        }
    }

    private void m554g() {
        if (this.f337d != null) {
            Arrays.fill(this.f337d, 0.0f);
            Arrays.fill(this.f338e, 0.0f);
            Arrays.fill(this.f339f, 0.0f);
            Arrays.fill(this.f340g, 0.0f);
            Arrays.fill(this.f341h, 0);
            Arrays.fill(this.f342i, 0);
            Arrays.fill(this.f343j, 0);
            this.f344k = 0;
        }
    }

    private void m555h() {
        this.f345l.computeCurrentVelocity(1000, this.f346m);
        m542a(m539a(C0056s.m369a(this.f345l, this.f336c), this.f347n, this.f346m), m539a(C0056s.m370b(this.f345l, this.f336c), this.f347n, this.f346m));
    }

    public int m556a() {
        return this.f334a;
    }

    public void m557a(View view, int i) {
        if (view.getParent() != this.f354u) {
            throw new IllegalArgumentException("captureChildView: parameter must be a descendant of the ViewDragHelper's tracked parent view (" + this.f354u + ")");
        }
        this.f352s = view;
        this.f336c = i;
        this.f351r.m444b(view, i);
        m564b(1);
    }

    public boolean m558a(int i) {
        return (this.f344k & (1 << i)) != 0;
    }

    public boolean m559a(int i, int i2) {
        if (this.f353t) {
            return m545a(i, i2, (int) C0056s.m369a(this.f345l, this.f336c), (int) C0056s.m370b(this.f345l, this.f336c));
        }
        throw new IllegalStateException("Cannot settleCapturedViewAt outside of a call to Callback#onViewReleased");
    }

    public boolean m560a(MotionEvent motionEvent) {
        int a = C0050m.m324a(motionEvent);
        int b = C0050m.m326b(motionEvent);
        if (a == 0) {
            m574e();
        }
        if (this.f345l == null) {
            this.f345l = VelocityTracker.obtain();
        }
        this.f345l.addMovement(motionEvent);
        float y;
        int b2;
        switch (a) {
            case 0:
                float x = motionEvent.getX();
                y = motionEvent.getY();
                b2 = C0050m.m327b(motionEvent, 0);
                m543a(x, y, b2);
                View d = m573d((int) x, (int) y);
                if (d == this.f352s && this.f334a == 2) {
                    m567b(d, b2);
                }
                a = this.f341h[b2];
                if ((this.f349p & a) != 0) {
                    this.f351r.m437a(a & this.f349p, b2);
                    break;
                }
                break;
            case 1:
            case 3:
                m574e();
                break;
            case 2:
                b = C0050m.m329c(motionEvent);
                a = 0;
                while (a < b) {
                    b2 = C0050m.m327b(motionEvent, a);
                    float c = C0050m.m328c(motionEvent, a);
                    float d2 = C0050m.m330d(motionEvent, a);
                    float f = c - this.f337d[b2];
                    float f2 = d2 - this.f338e[b2];
                    m548b(f, f2, b2);
                    if (this.f334a != 1) {
                        View d3 = m573d((int) c, (int) d2);
                        if (d3 == null || !m546a(d3, f, f2) || !m567b(d3, b2)) {
                            a++;
                        }
                    }
                    m550c(motionEvent);
                    break;
                }
                m550c(motionEvent);
                break;
            case 5:
                a = C0050m.m327b(motionEvent, b);
                float c2 = C0050m.m328c(motionEvent, b);
                y = C0050m.m330d(motionEvent, b);
                m543a(c2, y, a);
                if (this.f334a != 0) {
                    if (this.f334a == 2) {
                        View d4 = m573d((int) c2, (int) y);
                        if (d4 == this.f352s) {
                            m567b(d4, a);
                            break;
                        }
                    }
                }
                b = this.f341h[a];
                if ((this.f349p & b) != 0) {
                    this.f351r.m437a(b & this.f349p, a);
                    break;
                }
                break;
            case 6:
                m551d(C0050m.m327b(motionEvent, b));
                break;
        }
        return this.f334a == 1;
    }

    public boolean m561a(View view, int i, int i2) {
        this.f352s = view;
        this.f336c = -1;
        return m545a(i, i2, 0, 0);
    }

    public boolean m562a(boolean z) {
        if (this.f334a == 2) {
            boolean a;
            boolean f = this.f350q.m498f();
            int b = this.f350q.m494b();
            int c = this.f350q.m495c();
            int left = b - this.f352s.getLeft();
            int top = c - this.f352s.getTop();
            if (left != 0) {
                this.f352s.offsetLeftAndRight(left);
            }
            if (top != 0) {
                this.f352s.offsetTopAndBottom(top);
            }
            if (!(left == 0 && top == 0)) {
                this.f351r.m439a(this.f352s, b, c, left, top);
            }
            if (f && b == this.f350q.m496d() && c == this.f350q.m497e()) {
                this.f350q.m499g();
                a = this.f350q.m493a();
            } else {
                a = f;
            }
            if (!a) {
                if (z) {
                    this.f354u.post(this.f355w);
                } else {
                    m564b(0);
                }
            }
        }
        return this.f334a == 2;
    }

    public int m563b() {
        return this.f348o;
    }

    void m564b(int i) {
        if (this.f334a != i) {
            this.f334a = i;
            this.f351r.m436a(i);
            if (i == 0) {
                this.f352s = null;
            }
        }
    }

    public void m565b(MotionEvent motionEvent) {
        int i = 0;
        int a = C0050m.m324a(motionEvent);
        int b = C0050m.m326b(motionEvent);
        if (a == 0) {
            m574e();
        }
        if (this.f345l == null) {
            this.f345l = VelocityTracker.obtain();
        }
        this.f345l.addMovement(motionEvent);
        float x;
        float y;
        View d;
        int i2;
        switch (a) {
            case 0:
                x = motionEvent.getX();
                y = motionEvent.getY();
                i = C0050m.m327b(motionEvent, 0);
                d = m573d((int) x, (int) y);
                m543a(x, y, i);
                m567b(d, i);
                i2 = this.f341h[i];
                if ((this.f349p & i2) != 0) {
                    this.f351r.m437a(i2 & this.f349p, i);
                }
            case 1:
                if (this.f334a == 1) {
                    m555h();
                }
                m574e();
            case 2:
                if (this.f334a == 1) {
                    i = C0050m.m325a(motionEvent, this.f336c);
                    x = C0050m.m328c(motionEvent, i);
                    i2 = (int) (x - this.f339f[this.f336c]);
                    i = (int) (C0050m.m330d(motionEvent, i) - this.f340g[this.f336c]);
                    m549b(this.f352s.getLeft() + i2, this.f352s.getTop() + i, i2, i);
                    m550c(motionEvent);
                    return;
                }
                i2 = C0050m.m329c(motionEvent);
                while (i < i2) {
                    a = C0050m.m327b(motionEvent, i);
                    float c = C0050m.m328c(motionEvent, i);
                    float d2 = C0050m.m330d(motionEvent, i);
                    float f = c - this.f337d[a];
                    float f2 = d2 - this.f338e[a];
                    m548b(f, f2, a);
                    if (this.f334a != 1) {
                        d = m573d((int) c, (int) d2);
                        if (!m546a(d, f, f2) || !m567b(d, a)) {
                            i++;
                        }
                    }
                    m550c(motionEvent);
                }
                m550c(motionEvent);
            case 3:
                if (this.f334a == 1) {
                    m542a(0.0f, 0.0f);
                }
                m574e();
            case 5:
                i = C0050m.m327b(motionEvent, b);
                x = C0050m.m328c(motionEvent, b);
                y = C0050m.m330d(motionEvent, b);
                m543a(x, y, i);
                if (this.f334a == 0) {
                    m567b(m573d((int) x, (int) y), i);
                    i2 = this.f341h[i];
                    if ((this.f349p & i2) != 0) {
                        this.f351r.m437a(i2 & this.f349p, i);
                    }
                } else if (m571c((int) x, (int) y)) {
                    m567b(this.f352s, i);
                }
            case 6:
                a = C0050m.m327b(motionEvent, b);
                if (this.f334a == 1 && a == this.f336c) {
                    b = C0050m.m329c(motionEvent);
                    while (i < b) {
                        int b2 = C0050m.m327b(motionEvent, i);
                        if (b2 != this.f336c) {
                            if (m573d((int) C0050m.m328c(motionEvent, i), (int) C0050m.m330d(motionEvent, i)) == this.f352s && m567b(this.f352s, b2)) {
                                i = this.f336c;
                                if (i == -1) {
                                    m555h();
                                }
                            }
                        }
                        i++;
                    }
                    i = -1;
                    if (i == -1) {
                        m555h();
                    }
                }
                m551d(a);
            default:
        }
    }

    public boolean m566b(int i, int i2) {
        if (!m558a(i2)) {
            return false;
        }
        boolean z = (i & 1) == 1;
        boolean z2 = (i & 2) == 2;
        float f = this.f339f[i2] - this.f337d[i2];
        float f2 = this.f340g[i2] - this.f338e[i2];
        return (z && z2) ? (f * f) + (f2 * f2) > ((float) (this.f335b * this.f335b)) : z ? Math.abs(f) > ((float) this.f335b) : z2 ? Math.abs(f2) > ((float) this.f335b) : false;
    }

    boolean m567b(View view, int i) {
        if (view == this.f352s && this.f336c == i) {
            return true;
        }
        if (view == null || !this.f351r.m440a(view, i)) {
            return false;
        }
        this.f336c = i;
        m557a(view, i);
        return true;
    }

    public boolean m568b(View view, int i, int i2) {
        return view != null && i >= view.getLeft() && i < view.getRight() && i2 >= view.getTop() && i2 < view.getBottom();
    }

    public View m569c() {
        return this.f352s;
    }

    public boolean m570c(int i) {
        int length = this.f337d.length;
        for (int i2 = 0; i2 < length; i2++) {
            if (m566b(i, i2)) {
                return true;
            }
        }
        return false;
    }

    public boolean m571c(int i, int i2) {
        return m568b(this.f352s, i, i2);
    }

    public int m572d() {
        return this.f335b;
    }

    public View m573d(int i, int i2) {
        for (int childCount = this.f354u.getChildCount() - 1; childCount >= 0; childCount--) {
            View childAt = this.f354u.getChildAt(this.f351r.m446c(childCount));
            if (i >= childAt.getLeft() && i < childAt.getRight() && i2 >= childAt.getTop() && i2 < childAt.getBottom()) {
                return childAt;
            }
        }
        return null;
    }

    public void m574e() {
        this.f336c = -1;
        m554g();
        if (this.f345l != null) {
            this.f345l.recycle();
            this.f345l = null;
        }
    }

    public void m575f() {
        m574e();
        if (this.f334a == 2) {
            int b = this.f350q.m494b();
            int c = this.f350q.m495c();
            this.f350q.m499g();
            int b2 = this.f350q.m494b();
            int c2 = this.f350q.m495c();
            this.f351r.m439a(this.f352s, b2, c2, b2 - b, c2 - c);
        }
        m564b(0);
    }
}
