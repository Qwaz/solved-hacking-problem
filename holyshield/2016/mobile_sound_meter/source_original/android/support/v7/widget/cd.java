package android.support.v7.widget;

import android.os.SystemClock;
import android.support.v4.p004h.az;
import android.support.v7.p015b.C0243l;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnTouchListener;
import android.view.ViewConfiguration;

public abstract class cd implements OnTouchListener {
    private final float f984a;
    private final int f985b;
    private final int f986c;
    private final View f987d;
    private Runnable f988e;
    private Runnable f989f;
    private boolean f990g;
    private boolean f991h;
    private int f992i;
    private final int[] f993j;

    public cd(View view) {
        this.f993j = new int[2];
        this.f987d = view;
        this.f984a = (float) ViewConfiguration.get(view.getContext()).getScaledTouchSlop();
        this.f985b = ViewConfiguration.getTapTimeout();
        this.f986c = (this.f985b + ViewConfiguration.getLongPressTimeout()) / 2;
    }

    private boolean m2156a(MotionEvent motionEvent) {
        View view = this.f987d;
        if (!view.isEnabled()) {
            return false;
        }
        switch (az.m895a(motionEvent)) {
            case C0243l.View_android_theme /*0*/:
                this.f992i = motionEvent.getPointerId(0);
                this.f991h = false;
                if (this.f988e == null) {
                    this.f988e = new ce();
                }
                view.postDelayed(this.f988e, (long) this.f985b);
                if (this.f989f == null) {
                    this.f989f = new cf();
                }
                view.postDelayed(this.f989f, (long) this.f986c);
                return false;
            case C0243l.View_android_focusable /*1*/:
            case C0243l.View_paddingEnd /*3*/:
                m2162d();
                return false;
            case C0243l.View_paddingStart /*2*/:
                int findPointerIndex = motionEvent.findPointerIndex(this.f992i);
                if (findPointerIndex < 0 || m2157a(view, motionEvent.getX(findPointerIndex), motionEvent.getY(findPointerIndex), this.f984a)) {
                    return false;
                }
                m2162d();
                view.getParent().requestDisallowInterceptTouchEvent(true);
                return true;
            default:
                return false;
        }
    }

    private static boolean m2157a(View view, float f, float f2, float f3) {
        return f >= (-f3) && f2 >= (-f3) && f < ((float) (view.getRight() - view.getLeft())) + f3 && f2 < ((float) (view.getBottom() - view.getTop())) + f3;
    }

    private boolean m2158a(View view, MotionEvent motionEvent) {
        int[] iArr = this.f993j;
        view.getLocationOnScreen(iArr);
        motionEvent.offsetLocation((float) (-iArr[0]), (float) (-iArr[1]));
        return true;
    }

    private boolean m2160b(MotionEvent motionEvent) {
        boolean z = true;
        View view = this.f987d;
        by a = m2164a();
        if (a == null || !a.m2581k()) {
            return false;
        }
        View a2 = a.f1381g;
        if (a2 == null || !a2.isShown()) {
            return false;
        }
        MotionEvent obtainNoHistory = MotionEvent.obtainNoHistory(motionEvent);
        m2161b(view, obtainNoHistory);
        m2158a(a2, obtainNoHistory);
        boolean a3 = a2.m2650a(obtainNoHistory, this.f992i);
        obtainNoHistory.recycle();
        int a4 = az.m895a(motionEvent);
        boolean z2 = (a4 == 1 || a4 == 3) ? false : true;
        if (!(a3 && z2)) {
            z = false;
        }
        return z;
    }

    private boolean m2161b(View view, MotionEvent motionEvent) {
        int[] iArr = this.f993j;
        view.getLocationOnScreen(iArr);
        motionEvent.offsetLocation((float) iArr[0], (float) iArr[1]);
        return true;
    }

    private void m2162d() {
        if (this.f989f != null) {
            this.f987d.removeCallbacks(this.f989f);
        }
        if (this.f988e != null) {
            this.f987d.removeCallbacks(this.f988e);
        }
    }

    private void m2163e() {
        m2162d();
        View view = this.f987d;
        if (view.isEnabled() && !view.isLongClickable() && m2165b()) {
            view.getParent().requestDisallowInterceptTouchEvent(true);
            long uptimeMillis = SystemClock.uptimeMillis();
            MotionEvent obtain = MotionEvent.obtain(uptimeMillis, uptimeMillis, 3, 0.0f, 0.0f, 0);
            view.onTouchEvent(obtain);
            obtain.recycle();
            this.f990g = true;
            this.f991h = true;
        }
    }

    public abstract by m2164a();

    protected boolean m2165b() {
        by a = m2164a();
        if (!(a == null || a.m2581k())) {
            a.m2567c();
        }
        return true;
    }

    protected boolean m2166c() {
        by a = m2164a();
        if (a != null && a.m2581k()) {
            a.m2579i();
        }
        return true;
    }

    public boolean onTouch(View view, MotionEvent motionEvent) {
        boolean b;
        boolean z = this.f990g;
        if (z) {
            b = this.f991h ? m2160b(motionEvent) : m2160b(motionEvent) || !m2166c();
        } else {
            boolean z2 = m2156a(motionEvent) && m2165b();
            if (z2) {
                long uptimeMillis = SystemClock.uptimeMillis();
                MotionEvent obtain = MotionEvent.obtain(uptimeMillis, uptimeMillis, 3, 0.0f, 0.0f, 0);
                this.f987d.onTouchEvent(obtain);
                obtain.recycle();
            }
            b = z2;
        }
        this.f990g = b;
        return b || z;
    }
}
