package android.support.v4.view;

import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.support.v4.p001b.C0028a;
import android.support.v4.widget.C0066e;
import android.util.AttributeSet;
import android.util.Log;
import android.view.FocusFinder;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.SoundEffectConstants;
import android.view.VelocityTracker;
import android.view.View;
import android.view.View.BaseSavedState;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewParent;
import android.view.accessibility.AccessibilityEvent;
import android.view.animation.Interpolator;
import android.widget.Scroller;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;

public class ViewPager extends ViewGroup {
    private static final int[] f199a;
    private static final aw af;
    private static final Comparator f200c;
    private static final Interpolator f201d;
    private boolean f202A;
    private boolean f203B;
    private int f204C;
    private int f205D;
    private int f206E;
    private float f207F;
    private float f208G;
    private float f209H;
    private float f210I;
    private int f211J;
    private VelocityTracker f212K;
    private int f213L;
    private int f214M;
    private int f215N;
    private int f216O;
    private boolean f217P;
    private C0066e f218Q;
    private C0066e f219R;
    private boolean f220S;
    private boolean f221T;
    private boolean f222U;
    private int f223V;
    private as f224W;
    private as f225Z;
    private ar aa;
    private at ab;
    private Method ac;
    private int ad;
    private ArrayList ae;
    private final Runnable ag;
    private int ah;
    private int f226b;
    private final ArrayList f227e;
    private final ap f228f;
    private final Rect f229g;
    private C0055r f230h;
    private int f231i;
    private int f232j;
    private Parcelable f233k;
    private ClassLoader f234l;
    private Scroller f235m;
    private au f236n;
    private int f237o;
    private Drawable f238p;
    private int f239q;
    private int f240r;
    private float f241s;
    private float f242t;
    private int f243u;
    private int f244v;
    private boolean f245w;
    private boolean f246x;
    private boolean f247y;
    private int f248z;

    public class SavedState extends BaseSavedState {
        public static final Creator CREATOR;
        int f196a;
        Parcelable f197b;
        ClassLoader f198c;

        static {
            CREATOR = C0028a.m198a(new av());
        }

        SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel);
            if (classLoader == null) {
                classLoader = getClass().getClassLoader();
            }
            this.f196a = parcel.readInt();
            this.f197b = parcel.readParcelable(classLoader);
            this.f198c = classLoader;
        }

        public SavedState(Parcelable parcelable) {
            super(parcelable);
        }

        public String toString() {
            return "FragmentPager.SavedState{" + Integer.toHexString(System.identityHashCode(this)) + " position=" + this.f196a + "}";
        }

        public void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.f196a);
            parcel.writeParcelable(this.f197b, i);
        }
    }

    static {
        f199a = new int[]{16842931};
        f200c = new am();
        f201d = new an();
        af = new aw();
    }

    private int m211a(int i, float f, int i2, int i3) {
        if (Math.abs(i3) <= this.f215N || Math.abs(i2) <= this.f213L) {
            i = (int) ((i >= this.f231i ? 0.4f : 0.6f) + (((float) i) + f));
        } else if (i2 <= 0) {
            i++;
        }
        if (this.f227e.size() <= 0) {
            return i;
        }
        return Math.max(((ap) this.f227e.get(0)).f251b, Math.min(i, ((ap) this.f227e.get(this.f227e.size() - 1)).f251b));
    }

    private Rect m212a(Rect rect, View view) {
        Rect rect2 = rect == null ? new Rect() : rect;
        if (view == null) {
            rect2.set(0, 0, 0, 0);
            return rect2;
        }
        rect2.left = view.getLeft();
        rect2.right = view.getRight();
        rect2.top = view.getTop();
        rect2.bottom = view.getBottom();
        ViewPager parent = view.getParent();
        while ((parent instanceof ViewGroup) && parent != this) {
            ViewGroup viewGroup = parent;
            rect2.left += viewGroup.getLeft();
            rect2.right += viewGroup.getRight();
            rect2.top += viewGroup.getTop();
            rect2.bottom += viewGroup.getBottom();
            parent = viewGroup.getParent();
        }
        return rect2;
    }

    private void m213a(int i, int i2, int i3, int i4) {
        if (i2 <= 0 || this.f227e.isEmpty()) {
            ap b = m239b(this.f231i);
            int min = (int) ((b != null ? Math.min(b.f254e, this.f242t) : 0.0f) * ((float) ((i - getPaddingLeft()) - getPaddingRight())));
            if (min != getScrollX()) {
                m217a(false);
                scrollTo(min, getScrollY());
                return;
            }
            return;
        }
        int paddingLeft = (int) (((float) (((i - getPaddingLeft()) - getPaddingRight()) + i3)) * (((float) getScrollX()) / ((float) (((i2 - getPaddingLeft()) - getPaddingRight()) + i4))));
        scrollTo(paddingLeft, getScrollY());
        if (!this.f235m.isFinished()) {
            this.f235m.startScroll(paddingLeft, 0, (int) (m239b(this.f231i).f254e * ((float) i)), 0, this.f235m.getDuration() - this.f235m.timePassed());
        }
    }

    private void m214a(int i, boolean z, int i2, boolean z2) {
        int max;
        ap b = m239b(i);
        if (b != null) {
            max = (int) (Math.max(this.f241s, Math.min(b.f254e, this.f242t)) * ((float) getClientWidth()));
        } else {
            max = 0;
        }
        if (z) {
            m233a(max, 0, i2);
            if (z2 && this.f224W != null) {
                this.f224W.m292a(i);
            }
            if (z2 && this.f225Z != null) {
                this.f225Z.m292a(i);
                return;
            }
            return;
        }
        if (z2 && this.f224W != null) {
            this.f224W.m292a(i);
        }
        if (z2 && this.f225Z != null) {
            this.f225Z.m292a(i);
        }
        m217a(false);
        scrollTo(max, 0);
        m221d(max);
    }

    private void m215a(ap apVar, int i, ap apVar2) {
        float f;
        int i2;
        ap apVar3;
        int i3;
        int a = this.f230h.m352a();
        int clientWidth = getClientWidth();
        float f2 = clientWidth > 0 ? ((float) this.f237o) / ((float) clientWidth) : 0.0f;
        if (apVar2 != null) {
            clientWidth = apVar2.f251b;
            int i4;
            if (clientWidth < apVar.f251b) {
                f = (apVar2.f254e + apVar2.f253d) + f2;
                i4 = clientWidth + 1;
                i2 = 0;
                while (i4 <= apVar.f251b && i2 < this.f227e.size()) {
                    apVar3 = (ap) this.f227e.get(i2);
                    while (i4 > apVar3.f251b && i2 < this.f227e.size() - 1) {
                        i2++;
                        apVar3 = (ap) this.f227e.get(i2);
                    }
                    while (i4 < apVar3.f251b) {
                        f += this.f230h.m351a(i4) + f2;
                        i4++;
                    }
                    apVar3.f254e = f;
                    f += apVar3.f253d + f2;
                    i4++;
                }
            } else if (clientWidth > apVar.f251b) {
                i2 = this.f227e.size() - 1;
                f = apVar2.f254e;
                i4 = clientWidth - 1;
                while (i4 >= apVar.f251b && i2 >= 0) {
                    apVar3 = (ap) this.f227e.get(i2);
                    while (i4 < apVar3.f251b && i2 > 0) {
                        i2--;
                        apVar3 = (ap) this.f227e.get(i2);
                    }
                    while (i4 > apVar3.f251b) {
                        f -= this.f230h.m351a(i4) + f2;
                        i4--;
                    }
                    f -= apVar3.f253d + f2;
                    apVar3.f254e = f;
                    i4--;
                }
            }
        }
        int size = this.f227e.size();
        float f3 = apVar.f254e;
        i2 = apVar.f251b - 1;
        this.f241s = apVar.f251b == 0 ? apVar.f254e : -3.4028235E38f;
        this.f242t = apVar.f251b == a + -1 ? (apVar.f254e + apVar.f253d) - 1.0f : Float.MAX_VALUE;
        for (i3 = i - 1; i3 >= 0; i3--) {
            apVar3 = (ap) this.f227e.get(i3);
            f = f3;
            while (i2 > apVar3.f251b) {
                f -= this.f230h.m351a(i2) + f2;
                i2--;
            }
            f3 = f - (apVar3.f253d + f2);
            apVar3.f254e = f3;
            if (apVar3.f251b == 0) {
                this.f241s = f3;
            }
            i2--;
        }
        f3 = (apVar.f254e + apVar.f253d) + f2;
        i2 = apVar.f251b + 1;
        for (i3 = i + 1; i3 < size; i3++) {
            apVar3 = (ap) this.f227e.get(i3);
            f = f3;
            while (i2 < apVar3.f251b) {
                f = (this.f230h.m351a(i2) + f2) + f;
                i2++;
            }
            if (apVar3.f251b == a - 1) {
                this.f242t = (apVar3.f253d + f) - 1.0f;
            }
            apVar3.f254e = f;
            f3 = f + (apVar3.f253d + f2);
            i2++;
        }
        this.f221T = false;
    }

    private void m216a(MotionEvent motionEvent) {
        int b = C0050m.m326b(motionEvent);
        if (C0050m.m327b(motionEvent, b) == this.f211J) {
            b = b == 0 ? 1 : 0;
            this.f207F = C0050m.m328c(motionEvent, b);
            this.f211J = C0050m.m327b(motionEvent, b);
            if (this.f212K != null) {
                this.f212K.clear();
            }
        }
    }

    private void m217a(boolean z) {
        int scrollX;
        boolean z2 = this.ah == 2;
        if (z2) {
            setScrollingCacheEnabled(false);
            this.f235m.abortAnimation();
            scrollX = getScrollX();
            int scrollY = getScrollY();
            int currX = this.f235m.getCurrX();
            int currY = this.f235m.getCurrY();
            if (!(scrollX == currX && scrollY == currY)) {
                scrollTo(currX, currY);
            }
        }
        this.f247y = false;
        boolean z3 = z2;
        for (scrollX = 0; scrollX < this.f227e.size(); scrollX++) {
            ap apVar = (ap) this.f227e.get(scrollX);
            if (apVar.f252c) {
                apVar.f252c = false;
                z3 = true;
            }
        }
        if (!z3) {
            return;
        }
        if (z) {
            C0061x.m383a((View) this, this.ag);
        } else {
            this.ag.run();
        }
    }

    private boolean m218a(float f, float f2) {
        return (f < ((float) this.f205D) && f2 > 0.0f) || (f > ((float) (getWidth() - this.f205D)) && f2 < 0.0f);
    }

    private void m219b(boolean z) {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            C0061x.m381a(getChildAt(i), z ? 2 : 0, null);
        }
    }

    private boolean m220b(float f) {
        boolean z;
        float f2;
        boolean z2 = true;
        boolean z3 = false;
        float f3 = this.f207F - f;
        this.f207F = f;
        float scrollX = ((float) getScrollX()) + f3;
        int clientWidth = getClientWidth();
        float f4 = ((float) clientWidth) * this.f241s;
        float f5 = ((float) clientWidth) * this.f242t;
        ap apVar = (ap) this.f227e.get(0);
        ap apVar2 = (ap) this.f227e.get(this.f227e.size() - 1);
        if (apVar.f251b != 0) {
            f4 = apVar.f254e * ((float) clientWidth);
            z = false;
        } else {
            z = true;
        }
        if (apVar2.f251b != this.f230h.m352a() - 1) {
            f2 = apVar2.f254e * ((float) clientWidth);
            z2 = false;
        } else {
            f2 = f5;
        }
        if (scrollX < f4) {
            if (z) {
                z3 = this.f218Q.m464a(Math.abs(f4 - scrollX) / ((float) clientWidth));
            }
        } else if (scrollX > f2) {
            if (z2) {
                z3 = this.f219R.m464a(Math.abs(scrollX - f2) / ((float) clientWidth));
            }
            f4 = f2;
        } else {
            f4 = scrollX;
        }
        this.f207F += f4 - ((float) ((int) f4));
        scrollTo((int) f4, getScrollY());
        m221d((int) f4);
        return z3;
    }

    private boolean m221d(int i) {
        if (this.f227e.size() == 0) {
            this.f222U = false;
            m232a(0, 0.0f, 0);
            if (this.f222U) {
                return false;
            }
            throw new IllegalStateException("onPageScrolled did not call superclass implementation");
        }
        ap h = m225h();
        int clientWidth = getClientWidth();
        int i2 = this.f237o + clientWidth;
        float f = ((float) this.f237o) / ((float) clientWidth);
        int i3 = h.f251b;
        float f2 = ((((float) i) / ((float) clientWidth)) - h.f254e) / (h.f253d + f);
        clientWidth = (int) (((float) i2) * f2);
        this.f222U = false;
        m232a(i3, f2, clientWidth);
        if (this.f222U) {
            return true;
        }
        throw new IllegalStateException("onPageScrolled did not call superclass implementation");
    }

    private void m223f() {
        int i = 0;
        while (i < getChildCount()) {
            if (!((aq) getChildAt(i).getLayoutParams()).f255a) {
                removeViewAt(i);
                i--;
            }
            i++;
        }
    }

    private void m224g() {
        if (this.ad != 0) {
            if (this.ae == null) {
                this.ae = new ArrayList();
            } else {
                this.ae.clear();
            }
            int childCount = getChildCount();
            for (int i = 0; i < childCount; i++) {
                this.ae.add(getChildAt(i));
            }
            Collections.sort(this.ae, af);
        }
    }

    private int getClientWidth() {
        return (getMeasuredWidth() - getPaddingLeft()) - getPaddingRight();
    }

    private ap m225h() {
        int clientWidth = getClientWidth();
        float scrollX = clientWidth > 0 ? ((float) getScrollX()) / ((float) clientWidth) : 0.0f;
        float f = clientWidth > 0 ? ((float) this.f237o) / ((float) clientWidth) : 0.0f;
        float f2 = 0.0f;
        float f3 = 0.0f;
        int i = -1;
        int i2 = 0;
        Object obj = 1;
        ap apVar = null;
        while (i2 < this.f227e.size()) {
            int i3;
            ap apVar2;
            ap apVar3 = (ap) this.f227e.get(i2);
            ap apVar4;
            if (obj != null || apVar3.f251b == i + 1) {
                apVar4 = apVar3;
                i3 = i2;
                apVar2 = apVar4;
            } else {
                apVar3 = this.f228f;
                apVar3.f254e = (f2 + f3) + f;
                apVar3.f251b = i + 1;
                apVar3.f253d = this.f230h.m351a(apVar3.f251b);
                apVar4 = apVar3;
                i3 = i2 - 1;
                apVar2 = apVar4;
            }
            f2 = apVar2.f254e;
            f3 = (apVar2.f253d + f2) + f;
            if (obj == null && scrollX < f2) {
                return apVar;
            }
            if (scrollX < f3 || i3 == this.f227e.size() - 1) {
                return apVar2;
            }
            f3 = f2;
            i = apVar2.f251b;
            obj = null;
            f2 = apVar2.f253d;
            apVar = apVar2;
            i2 = i3 + 1;
        }
        return apVar;
    }

    private void m226i() {
        this.f202A = false;
        this.f203B = false;
        if (this.f212K != null) {
            this.f212K.recycle();
            this.f212K = null;
        }
    }

    private void setScrollState(int i) {
        if (this.ah != i) {
            this.ah = i;
            if (this.ab != null) {
                m219b(i != 0);
            }
            if (this.f224W != null) {
                this.f224W.m294b(i);
            }
        }
    }

    private void setScrollingCacheEnabled(boolean z) {
        if (this.f246x != z) {
            this.f246x = z;
        }
    }

    float m227a(float f) {
        return (float) Math.sin((double) ((float) (((double) (f - 0.5f)) * 0.4712389167638204d)));
    }

    ap m228a(int i, int i2) {
        ap apVar = new ap();
        apVar.f251b = i;
        apVar.f250a = this.f230h.m355a((ViewGroup) this, i);
        apVar.f253d = this.f230h.m351a(i);
        if (i2 < 0 || i2 >= this.f227e.size()) {
            this.f227e.add(apVar);
        } else {
            this.f227e.add(i2, apVar);
        }
        return apVar;
    }

    ap m229a(View view) {
        for (int i = 0; i < this.f227e.size(); i++) {
            ap apVar = (ap) this.f227e.get(i);
            if (this.f230h.m362a(view, apVar.f250a)) {
                return apVar;
            }
        }
        return null;
    }

    void m230a() {
        int a = this.f230h.m352a();
        this.f226b = a;
        boolean z = this.f227e.size() < (this.f248z * 2) + 1 && this.f227e.size() < a;
        boolean z2 = false;
        int i = this.f231i;
        boolean z3 = z;
        int i2 = 0;
        while (i2 < this.f227e.size()) {
            int i3;
            boolean z4;
            int i4;
            boolean z5;
            ap apVar = (ap) this.f227e.get(i2);
            int a2 = this.f230h.m353a(apVar.f250a);
            if (a2 == -1) {
                i3 = i2;
                z4 = z2;
                i4 = i;
                z5 = z3;
            } else if (a2 == -2) {
                this.f227e.remove(i2);
                i2--;
                if (!z2) {
                    this.f230h.m360a((ViewGroup) this);
                    z2 = true;
                }
                this.f230h.m361a((ViewGroup) this, apVar.f251b, apVar.f250a);
                if (this.f231i == apVar.f251b) {
                    i3 = i2;
                    z4 = z2;
                    i4 = Math.max(0, Math.min(this.f231i, a - 1));
                    z5 = true;
                } else {
                    i3 = i2;
                    z4 = z2;
                    i4 = i;
                    z5 = true;
                }
            } else if (apVar.f251b != a2) {
                if (apVar.f251b == this.f231i) {
                    i = a2;
                }
                apVar.f251b = a2;
                i3 = i2;
                z4 = z2;
                i4 = i;
                z5 = true;
            } else {
                i3 = i2;
                z4 = z2;
                i4 = i;
                z5 = z3;
            }
            z3 = z5;
            i = i4;
            z2 = z4;
            i2 = i3 + 1;
        }
        if (z2) {
            this.f230h.m367b((ViewGroup) this);
        }
        Collections.sort(this.f227e, f200c);
        if (z3) {
            i4 = getChildCount();
            for (i2 = 0; i2 < i4; i2++) {
                aq aqVar = (aq) getChildAt(i2).getLayoutParams();
                if (!aqVar.f255a) {
                    aqVar.f257c = 0.0f;
                }
            }
            m235a(i, false, true);
            requestLayout();
        }
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    void m231a(int r19) {
        /*
        r18 = this;
        r3 = 0;
        r2 = 2;
        r0 = r18;
        r4 = r0.f231i;
        r0 = r19;
        if (r4 == r0) goto L_0x033f;
    L_0x000a:
        r0 = r18;
        r2 = r0.f231i;
        r0 = r19;
        if (r2 >= r0) goto L_0x0030;
    L_0x0012:
        r2 = 66;
    L_0x0014:
        r0 = r18;
        r3 = r0.f231i;
        r0 = r18;
        r3 = r0.m239b(r3);
        r0 = r19;
        r1 = r18;
        r1.f231i = r0;
        r4 = r3;
        r3 = r2;
    L_0x0026:
        r0 = r18;
        r2 = r0.f230h;
        if (r2 != 0) goto L_0x0033;
    L_0x002c:
        r18.m224g();
    L_0x002f:
        return;
    L_0x0030:
        r2 = 17;
        goto L_0x0014;
    L_0x0033:
        r0 = r18;
        r2 = r0.f247y;
        if (r2 == 0) goto L_0x003d;
    L_0x0039:
        r18.m224g();
        goto L_0x002f;
    L_0x003d:
        r2 = r18.getWindowToken();
        if (r2 == 0) goto L_0x002f;
    L_0x0043:
        r0 = r18;
        r2 = r0.f230h;
        r0 = r18;
        r2.m360a(r0);
        r0 = r18;
        r2 = r0.f248z;
        r5 = 0;
        r0 = r18;
        r6 = r0.f231i;
        r6 = r6 - r2;
        r11 = java.lang.Math.max(r5, r6);
        r0 = r18;
        r5 = r0.f230h;
        r12 = r5.m352a();
        r5 = r12 + -1;
        r0 = r18;
        r6 = r0.f231i;
        r2 = r2 + r6;
        r13 = java.lang.Math.min(r5, r2);
        r0 = r18;
        r2 = r0.f226b;
        if (r12 == r2) goto L_0x00da;
    L_0x0073:
        r2 = r18.getResources();	 Catch:{ NotFoundException -> 0x00d0 }
        r3 = r18.getId();	 Catch:{ NotFoundException -> 0x00d0 }
        r2 = r2.getResourceName(r3);	 Catch:{ NotFoundException -> 0x00d0 }
    L_0x007f:
        r3 = new java.lang.IllegalStateException;
        r4 = new java.lang.StringBuilder;
        r4.<init>();
        r5 = "The application's PagerAdapter changed the adapter's contents without calling PagerAdapter#notifyDataSetChanged! Expected adapter item count: ";
        r4 = r4.append(r5);
        r0 = r18;
        r5 = r0.f226b;
        r4 = r4.append(r5);
        r5 = ", found: ";
        r4 = r4.append(r5);
        r4 = r4.append(r12);
        r5 = " Pager id: ";
        r4 = r4.append(r5);
        r2 = r4.append(r2);
        r4 = " Pager class: ";
        r2 = r2.append(r4);
        r4 = r18.getClass();
        r2 = r2.append(r4);
        r4 = " Problematic adapter: ";
        r2 = r2.append(r4);
        r0 = r18;
        r4 = r0.f230h;
        r4 = r4.getClass();
        r2 = r2.append(r4);
        r2 = r2.toString();
        r3.<init>(r2);
        throw r3;
    L_0x00d0:
        r2 = move-exception;
        r2 = r18.getId();
        r2 = java.lang.Integer.toHexString(r2);
        goto L_0x007f;
    L_0x00da:
        r6 = 0;
        r2 = 0;
        r5 = r2;
    L_0x00dd:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.size();
        if (r5 >= r2) goto L_0x033c;
    L_0x00e7:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r5);
        r2 = (android.support.v4.view.ap) r2;
        r7 = r2.f251b;
        r0 = r18;
        r8 = r0.f231i;
        if (r7 < r8) goto L_0x01cf;
    L_0x00f9:
        r7 = r2.f251b;
        r0 = r18;
        r8 = r0.f231i;
        if (r7 != r8) goto L_0x033c;
    L_0x0101:
        if (r2 != 0) goto L_0x0339;
    L_0x0103:
        if (r12 <= 0) goto L_0x0339;
    L_0x0105:
        r0 = r18;
        r2 = r0.f231i;
        r0 = r18;
        r2 = r0.m228a(r2, r5);
        r10 = r2;
    L_0x0110:
        if (r10 == 0) goto L_0x0180;
    L_0x0112:
        r9 = 0;
        r8 = r5 + -1;
        if (r8 < 0) goto L_0x01d4;
    L_0x0117:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r8);
        r2 = (android.support.v4.view.ap) r2;
    L_0x0121:
        r14 = r18.getClientWidth();
        if (r14 > 0) goto L_0x01d7;
    L_0x0127:
        r6 = 0;
    L_0x0128:
        r0 = r18;
        r7 = r0.f231i;
        r7 = r7 + -1;
        r16 = r7;
        r7 = r9;
        r9 = r16;
        r17 = r8;
        r8 = r5;
        r5 = r17;
    L_0x0138:
        if (r9 < 0) goto L_0x0142;
    L_0x013a:
        r15 = (r7 > r6 ? 1 : (r7 == r6 ? 0 : -1));
        if (r15 < 0) goto L_0x0216;
    L_0x013e:
        if (r9 >= r11) goto L_0x0216;
    L_0x0140:
        if (r2 != 0) goto L_0x01e6;
    L_0x0142:
        r6 = r10.f253d;
        r9 = r8 + 1;
        r2 = 1073741824; // 0x40000000 float:2.0 double:5.304989477E-315;
        r2 = (r6 > r2 ? 1 : (r6 == r2 ? 0 : -1));
        if (r2 >= 0) goto L_0x017b;
    L_0x014c:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.size();
        if (r9 >= r2) goto L_0x024c;
    L_0x0156:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r9);
        r2 = (android.support.v4.view.ap) r2;
        r7 = r2;
    L_0x0161:
        if (r14 > 0) goto L_0x024f;
    L_0x0163:
        r2 = 0;
        r5 = r2;
    L_0x0165:
        r0 = r18;
        r2 = r0.f231i;
        r2 = r2 + 1;
        r16 = r2;
        r2 = r7;
        r7 = r9;
        r9 = r16;
    L_0x0171:
        if (r9 >= r12) goto L_0x017b;
    L_0x0173:
        r11 = (r6 > r5 ? 1 : (r6 == r5 ? 0 : -1));
        if (r11 < 0) goto L_0x029a;
    L_0x0177:
        if (r9 <= r13) goto L_0x029a;
    L_0x0179:
        if (r2 != 0) goto L_0x025c;
    L_0x017b:
        r0 = r18;
        r0.m215a(r10, r8, r4);
    L_0x0180:
        r0 = r18;
        r4 = r0.f230h;
        r0 = r18;
        r5 = r0.f231i;
        if (r10 == 0) goto L_0x02e8;
    L_0x018a:
        r2 = r10.f250a;
    L_0x018c:
        r0 = r18;
        r4.m368b(r0, r5, r2);
        r0 = r18;
        r2 = r0.f230h;
        r0 = r18;
        r2.m367b(r0);
        r5 = r18.getChildCount();
        r2 = 0;
        r4 = r2;
    L_0x01a0:
        if (r4 >= r5) goto L_0x02eb;
    L_0x01a2:
        r0 = r18;
        r6 = r0.getChildAt(r4);
        r2 = r6.getLayoutParams();
        r2 = (android.support.v4.view.aq) r2;
        r2.f260f = r4;
        r7 = r2.f255a;
        if (r7 != 0) goto L_0x01cb;
    L_0x01b4:
        r7 = r2.f257c;
        r8 = 0;
        r7 = (r7 > r8 ? 1 : (r7 == r8 ? 0 : -1));
        if (r7 != 0) goto L_0x01cb;
    L_0x01bb:
        r0 = r18;
        r6 = r0.m229a(r6);
        if (r6 == 0) goto L_0x01cb;
    L_0x01c3:
        r7 = r6.f253d;
        r2.f257c = r7;
        r6 = r6.f251b;
        r2.f259e = r6;
    L_0x01cb:
        r2 = r4 + 1;
        r4 = r2;
        goto L_0x01a0;
    L_0x01cf:
        r2 = r5 + 1;
        r5 = r2;
        goto L_0x00dd;
    L_0x01d4:
        r2 = 0;
        goto L_0x0121;
    L_0x01d7:
        r6 = 1073741824; // 0x40000000 float:2.0 double:5.304989477E-315;
        r7 = r10.f253d;
        r6 = r6 - r7;
        r7 = r18.getPaddingLeft();
        r7 = (float) r7;
        r15 = (float) r14;
        r7 = r7 / r15;
        r6 = r6 + r7;
        goto L_0x0128;
    L_0x01e6:
        r15 = r2.f251b;
        if (r9 != r15) goto L_0x0210;
    L_0x01ea:
        r15 = r2.f252c;
        if (r15 != 0) goto L_0x0210;
    L_0x01ee:
        r0 = r18;
        r15 = r0.f227e;
        r15.remove(r5);
        r0 = r18;
        r15 = r0.f230h;
        r2 = r2.f250a;
        r0 = r18;
        r15.m361a(r0, r9, r2);
        r5 = r5 + -1;
        r8 = r8 + -1;
        if (r5 < 0) goto L_0x0214;
    L_0x0206:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r5);
        r2 = (android.support.v4.view.ap) r2;
    L_0x0210:
        r9 = r9 + -1;
        goto L_0x0138;
    L_0x0214:
        r2 = 0;
        goto L_0x0210;
    L_0x0216:
        if (r2 == 0) goto L_0x0230;
    L_0x0218:
        r15 = r2.f251b;
        if (r9 != r15) goto L_0x0230;
    L_0x021c:
        r2 = r2.f253d;
        r7 = r7 + r2;
        r5 = r5 + -1;
        if (r5 < 0) goto L_0x022e;
    L_0x0223:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r5);
        r2 = (android.support.v4.view.ap) r2;
        goto L_0x0210;
    L_0x022e:
        r2 = 0;
        goto L_0x0210;
    L_0x0230:
        r2 = r5 + 1;
        r0 = r18;
        r2 = r0.m228a(r9, r2);
        r2 = r2.f253d;
        r7 = r7 + r2;
        r8 = r8 + 1;
        if (r5 < 0) goto L_0x024a;
    L_0x023f:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r5);
        r2 = (android.support.v4.view.ap) r2;
        goto L_0x0210;
    L_0x024a:
        r2 = 0;
        goto L_0x0210;
    L_0x024c:
        r7 = 0;
        goto L_0x0161;
    L_0x024f:
        r2 = r18.getPaddingRight();
        r2 = (float) r2;
        r5 = (float) r14;
        r2 = r2 / r5;
        r5 = 1073741824; // 0x40000000 float:2.0 double:5.304989477E-315;
        r2 = r2 + r5;
        r5 = r2;
        goto L_0x0165;
    L_0x025c:
        r11 = r2.f251b;
        if (r9 != r11) goto L_0x0332;
    L_0x0260:
        r11 = r2.f252c;
        if (r11 != 0) goto L_0x0332;
    L_0x0264:
        r0 = r18;
        r11 = r0.f227e;
        r11.remove(r7);
        r0 = r18;
        r11 = r0.f230h;
        r2 = r2.f250a;
        r0 = r18;
        r11.m361a(r0, r9, r2);
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.size();
        if (r7 >= r2) goto L_0x0298;
    L_0x0280:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r7);
        r2 = (android.support.v4.view.ap) r2;
    L_0x028a:
        r16 = r6;
        r6 = r2;
        r2 = r16;
    L_0x028f:
        r9 = r9 + 1;
        r16 = r2;
        r2 = r6;
        r6 = r16;
        goto L_0x0171;
    L_0x0298:
        r2 = 0;
        goto L_0x028a;
    L_0x029a:
        if (r2 == 0) goto L_0x02c1;
    L_0x029c:
        r11 = r2.f251b;
        if (r9 != r11) goto L_0x02c1;
    L_0x02a0:
        r2 = r2.f253d;
        r6 = r6 + r2;
        r7 = r7 + 1;
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.size();
        if (r7 >= r2) goto L_0x02bf;
    L_0x02af:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r7);
        r2 = (android.support.v4.view.ap) r2;
    L_0x02b9:
        r16 = r6;
        r6 = r2;
        r2 = r16;
        goto L_0x028f;
    L_0x02bf:
        r2 = 0;
        goto L_0x02b9;
    L_0x02c1:
        r0 = r18;
        r2 = r0.m228a(r9, r7);
        r7 = r7 + 1;
        r2 = r2.f253d;
        r6 = r6 + r2;
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.size();
        if (r7 >= r2) goto L_0x02e6;
    L_0x02d6:
        r0 = r18;
        r2 = r0.f227e;
        r2 = r2.get(r7);
        r2 = (android.support.v4.view.ap) r2;
    L_0x02e0:
        r16 = r6;
        r6 = r2;
        r2 = r16;
        goto L_0x028f;
    L_0x02e6:
        r2 = 0;
        goto L_0x02e0;
    L_0x02e8:
        r2 = 0;
        goto L_0x018c;
    L_0x02eb:
        r18.m224g();
        r2 = r18.hasFocus();
        if (r2 == 0) goto L_0x002f;
    L_0x02f4:
        r2 = r18.findFocus();
        if (r2 == 0) goto L_0x0330;
    L_0x02fa:
        r0 = r18;
        r2 = r0.m240b(r2);
    L_0x0300:
        if (r2 == 0) goto L_0x030a;
    L_0x0302:
        r2 = r2.f251b;
        r0 = r18;
        r4 = r0.f231i;
        if (r2 == r4) goto L_0x002f;
    L_0x030a:
        r2 = 0;
    L_0x030b:
        r4 = r18.getChildCount();
        if (r2 >= r4) goto L_0x002f;
    L_0x0311:
        r0 = r18;
        r4 = r0.getChildAt(r2);
        r0 = r18;
        r5 = r0.m229a(r4);
        if (r5 == 0) goto L_0x032d;
    L_0x031f:
        r5 = r5.f251b;
        r0 = r18;
        r6 = r0.f231i;
        if (r5 != r6) goto L_0x032d;
    L_0x0327:
        r4 = r4.requestFocus(r3);
        if (r4 != 0) goto L_0x002f;
    L_0x032d:
        r2 = r2 + 1;
        goto L_0x030b;
    L_0x0330:
        r2 = 0;
        goto L_0x0300;
    L_0x0332:
        r16 = r6;
        r6 = r2;
        r2 = r16;
        goto L_0x028f;
    L_0x0339:
        r10 = r2;
        goto L_0x0110;
    L_0x033c:
        r2 = r6;
        goto L_0x0101;
    L_0x033f:
        r4 = r3;
        r3 = r2;
        goto L_0x0026;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.view.ViewPager.a(int):void");
    }

    protected void m232a(int i, float f, int i2) {
        int paddingLeft;
        int paddingRight;
        int i3;
        if (this.f223V > 0) {
            int scrollX = getScrollX();
            paddingLeft = getPaddingLeft();
            paddingRight = getPaddingRight();
            int width = getWidth();
            int childCount = getChildCount();
            i3 = 0;
            while (i3 < childCount) {
                int i4;
                View childAt = getChildAt(i3);
                aq aqVar = (aq) childAt.getLayoutParams();
                if (aqVar.f255a) {
                    int max;
                    switch (aqVar.f256b & 7) {
                        case 1:
                            max = Math.max((width - childAt.getMeasuredWidth()) / 2, paddingLeft);
                            i4 = paddingRight;
                            paddingRight = paddingLeft;
                            paddingLeft = i4;
                            break;
                        case 3:
                            max = childAt.getWidth() + paddingLeft;
                            i4 = paddingLeft;
                            paddingLeft = paddingRight;
                            paddingRight = max;
                            max = i4;
                            break;
                        case 5:
                            max = (width - paddingRight) - childAt.getMeasuredWidth();
                            i4 = paddingRight + childAt.getMeasuredWidth();
                            paddingRight = paddingLeft;
                            paddingLeft = i4;
                            break;
                        default:
                            max = paddingLeft;
                            i4 = paddingRight;
                            paddingRight = paddingLeft;
                            paddingLeft = i4;
                            break;
                    }
                    max = (max + scrollX) - childAt.getLeft();
                    if (max != 0) {
                        childAt.offsetLeftAndRight(max);
                    }
                } else {
                    i4 = paddingRight;
                    paddingRight = paddingLeft;
                    paddingLeft = i4;
                }
                i3++;
                i4 = paddingLeft;
                paddingLeft = paddingRight;
                paddingRight = i4;
            }
        }
        if (this.f224W != null) {
            this.f224W.m293a(i, f, i2);
        }
        if (this.f225Z != null) {
            this.f225Z.m293a(i, f, i2);
        }
        if (this.ab != null) {
            paddingRight = getScrollX();
            i3 = getChildCount();
            for (paddingLeft = 0; paddingLeft < i3; paddingLeft++) {
                View childAt2 = getChildAt(paddingLeft);
                if (!((aq) childAt2.getLayoutParams()).f255a) {
                    this.ab.m295a(childAt2, ((float) (childAt2.getLeft() - paddingRight)) / ((float) getClientWidth()));
                }
            }
        }
        this.f222U = true;
    }

    void m233a(int i, int i2, int i3) {
        if (getChildCount() == 0) {
            setScrollingCacheEnabled(false);
            return;
        }
        int scrollX = getScrollX();
        int scrollY = getScrollY();
        int i4 = i - scrollX;
        int i5 = i2 - scrollY;
        if (i4 == 0 && i5 == 0) {
            m217a(false);
            m241b();
            setScrollState(0);
            return;
        }
        setScrollingCacheEnabled(true);
        setScrollState(2);
        int clientWidth = getClientWidth();
        int i6 = clientWidth / 2;
        float a = (((float) i6) * m227a(Math.min(1.0f, (((float) Math.abs(i4)) * 1.0f) / ((float) clientWidth)))) + ((float) i6);
        int abs = Math.abs(i3);
        if (abs > 0) {
            clientWidth = Math.round(1000.0f * Math.abs(a / ((float) abs))) * 4;
        } else {
            clientWidth = (int) (((((float) Math.abs(i4)) / ((((float) clientWidth) * this.f230h.m351a(this.f231i)) + ((float) this.f237o))) + 1.0f) * 100.0f);
        }
        this.f235m.startScroll(scrollX, scrollY, i4, i5, Math.min(clientWidth, 600));
        C0061x.m385b(this);
    }

    public void m234a(int i, boolean z) {
        this.f247y = false;
        m235a(i, z, false);
    }

    void m235a(int i, boolean z, boolean z2) {
        m236a(i, z, z2, 0);
    }

    void m236a(int i, boolean z, boolean z2, int i2) {
        boolean z3 = false;
        if (this.f230h == null || this.f230h.m352a() <= 0) {
            setScrollingCacheEnabled(false);
        } else if (z2 || this.f231i != i || this.f227e.size() == 0) {
            if (i < 0) {
                i = 0;
            } else if (i >= this.f230h.m352a()) {
                i = this.f230h.m352a() - 1;
            }
            int i3 = this.f248z;
            if (i > this.f231i + i3 || i < this.f231i - i3) {
                for (int i4 = 0; i4 < this.f227e.size(); i4++) {
                    ((ap) this.f227e.get(i4)).f252c = true;
                }
            }
            if (this.f231i != i) {
                z3 = true;
            }
            if (this.f220S) {
                this.f231i = i;
                if (z3 && this.f224W != null) {
                    this.f224W.m292a(i);
                }
                if (z3 && this.f225Z != null) {
                    this.f225Z.m292a(i);
                }
                requestLayout();
                return;
            }
            m231a(i);
            m214a(i, z, i2, z3);
        } else {
            setScrollingCacheEnabled(false);
        }
    }

    public boolean m237a(KeyEvent keyEvent) {
        if (keyEvent.getAction() != 0) {
            return false;
        }
        switch (keyEvent.getKeyCode()) {
            case 21:
                return m243c(17);
            case 22:
                return m243c(66);
            case 61:
                return VERSION.SDK_INT >= 11 ? C0043f.m305a(keyEvent) ? m243c(2) : C0043f.m306a(keyEvent, 1) ? m243c(1) : false : false;
            default:
                return false;
        }
    }

    protected boolean m238a(View view, boolean z, int i, int i2, int i3) {
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            int scrollX = view.getScrollX();
            int scrollY = view.getScrollY();
            for (int childCount = viewGroup.getChildCount() - 1; childCount >= 0; childCount--) {
                View childAt = viewGroup.getChildAt(childCount);
                if (i2 + scrollX >= childAt.getLeft() && i2 + scrollX < childAt.getRight() && i3 + scrollY >= childAt.getTop() && i3 + scrollY < childAt.getBottom()) {
                    if (m238a(childAt, true, i, (i2 + scrollX) - childAt.getLeft(), (i3 + scrollY) - childAt.getTop())) {
                        return true;
                    }
                }
            }
        }
        return z && C0061x.m384a(view, -i);
    }

    public void addFocusables(ArrayList arrayList, int i, int i2) {
        int size = arrayList.size();
        int descendantFocusability = getDescendantFocusability();
        if (descendantFocusability != 393216) {
            for (int i3 = 0; i3 < getChildCount(); i3++) {
                View childAt = getChildAt(i3);
                if (childAt.getVisibility() == 0) {
                    ap a = m229a(childAt);
                    if (a != null && a.f251b == this.f231i) {
                        childAt.addFocusables(arrayList, i, i2);
                    }
                }
            }
        }
        if ((descendantFocusability == 262144 && size != arrayList.size()) || !isFocusable()) {
            return;
        }
        if (((i2 & 1) != 1 || !isInTouchMode() || isFocusableInTouchMode()) && arrayList != null) {
            arrayList.add(this);
        }
    }

    public void addTouchables(ArrayList arrayList) {
        for (int i = 0; i < getChildCount(); i++) {
            View childAt = getChildAt(i);
            if (childAt.getVisibility() == 0) {
                ap a = m229a(childAt);
                if (a != null && a.f251b == this.f231i) {
                    childAt.addTouchables(arrayList);
                }
            }
        }
    }

    public void addView(View view, int i, LayoutParams layoutParams) {
        LayoutParams generateLayoutParams = !checkLayoutParams(layoutParams) ? generateLayoutParams(layoutParams) : layoutParams;
        aq aqVar = (aq) generateLayoutParams;
        aqVar.f255a |= view instanceof ao;
        if (!this.f245w) {
            super.addView(view, i, generateLayoutParams);
        } else if (aqVar == null || !aqVar.f255a) {
            aqVar.f258d = true;
            addViewInLayout(view, i, generateLayoutParams);
        } else {
            throw new IllegalStateException("Cannot add pager decor view during layout");
        }
    }

    ap m239b(int i) {
        for (int i2 = 0; i2 < this.f227e.size(); i2++) {
            ap apVar = (ap) this.f227e.get(i2);
            if (apVar.f251b == i) {
                return apVar;
            }
        }
        return null;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    android.support.v4.view.ap m240b(android.view.View r3) {
        /*
        r2 = this;
    L_0x0000:
        r0 = r3.getParent();
        if (r0 == r2) goto L_0x0012;
    L_0x0006:
        if (r0 == 0) goto L_0x000c;
    L_0x0008:
        r1 = r0 instanceof android.view.View;
        if (r1 != 0) goto L_0x000e;
    L_0x000c:
        r0 = 0;
    L_0x000d:
        return r0;
    L_0x000e:
        r0 = (android.view.View) r0;
        r3 = r0;
        goto L_0x0000;
    L_0x0012:
        r0 = r2.m229a(r3);
        goto L_0x000d;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.view.ViewPager.b(android.view.View):android.support.v4.view.ap");
    }

    void m241b() {
        m231a(this.f231i);
    }

    boolean m242c() {
        if (this.f231i <= 0) {
            return false;
        }
        m234a(this.f231i - 1, true);
        return true;
    }

    public boolean m243c(int i) {
        View view;
        boolean c;
        View findFocus = findFocus();
        if (findFocus == this) {
            view = null;
        } else {
            if (findFocus != null) {
                Object obj;
                for (ViewPager parent = findFocus.getParent(); parent instanceof ViewGroup; parent = parent.getParent()) {
                    if (parent == this) {
                        obj = 1;
                        break;
                    }
                }
                obj = null;
                if (obj == null) {
                    StringBuilder stringBuilder = new StringBuilder();
                    stringBuilder.append(findFocus.getClass().getSimpleName());
                    for (ViewParent parent2 = findFocus.getParent(); parent2 instanceof ViewGroup; parent2 = parent2.getParent()) {
                        stringBuilder.append(" => ").append(parent2.getClass().getSimpleName());
                    }
                    Log.e("ViewPager", "arrowScroll tried to find focus based on non-child current focused view " + stringBuilder.toString());
                    view = null;
                }
            }
            view = findFocus;
        }
        View findNextFocus = FocusFinder.getInstance().findNextFocus(this, view, i);
        if (findNextFocus == null || findNextFocus == view) {
            if (i == 17 || i == 1) {
                c = m242c();
            } else {
                if (i == 66 || i == 2) {
                    c = m244d();
                }
                c = false;
            }
        } else if (i == 17) {
            c = (view == null || m212a(this.f229g, findNextFocus).left < m212a(this.f229g, view).left) ? findNextFocus.requestFocus() : m242c();
        } else {
            if (i == 66) {
                c = (view == null || m212a(this.f229g, findNextFocus).left > m212a(this.f229g, view).left) ? findNextFocus.requestFocus() : m244d();
            }
            c = false;
        }
        if (c) {
            playSoundEffect(SoundEffectConstants.getContantForFocusDirection(i));
        }
        return c;
    }

    public boolean canScrollHorizontally(int i) {
        boolean z = true;
        if (this.f230h == null) {
            return false;
        }
        int clientWidth = getClientWidth();
        int scrollX = getScrollX();
        if (i < 0) {
            if (scrollX <= ((int) (((float) clientWidth) * this.f241s))) {
                z = false;
            }
            return z;
        } else if (i <= 0) {
            return false;
        } else {
            if (scrollX >= ((int) (((float) clientWidth) * this.f242t))) {
                z = false;
            }
            return z;
        }
    }

    protected boolean checkLayoutParams(LayoutParams layoutParams) {
        return (layoutParams instanceof aq) && super.checkLayoutParams(layoutParams);
    }

    public void computeScroll() {
        if (this.f235m.isFinished() || !this.f235m.computeScrollOffset()) {
            m217a(true);
            return;
        }
        int scrollX = getScrollX();
        int scrollY = getScrollY();
        int currX = this.f235m.getCurrX();
        int currY = this.f235m.getCurrY();
        if (!(scrollX == currX && scrollY == currY)) {
            scrollTo(currX, currY);
            if (!m221d(currX)) {
                this.f235m.abortAnimation();
                scrollTo(0, currY);
            }
        }
        C0061x.m385b(this);
    }

    boolean m244d() {
        if (this.f230h == null || this.f231i >= this.f230h.m352a() - 1) {
            return false;
        }
        m234a(this.f231i + 1, true);
        return true;
    }

    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        return super.dispatchKeyEvent(keyEvent) || m237a(keyEvent);
    }

    public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        if (accessibilityEvent.getEventType() == 4096) {
            return super.dispatchPopulateAccessibilityEvent(accessibilityEvent);
        }
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            if (childAt.getVisibility() == 0) {
                ap a = m229a(childAt);
                if (a != null && a.f251b == this.f231i && childAt.dispatchPopulateAccessibilityEvent(accessibilityEvent)) {
                    return true;
                }
            }
        }
        return false;
    }

    public void draw(Canvas canvas) {
        super.draw(canvas);
        int i = 0;
        int a = C0061x.m379a(this);
        if (a == 0 || (a == 1 && this.f230h != null && this.f230h.m352a() > 1)) {
            int height;
            int width;
            if (!this.f218Q.m463a()) {
                a = canvas.save();
                height = (getHeight() - getPaddingTop()) - getPaddingBottom();
                width = getWidth();
                canvas.rotate(270.0f);
                canvas.translate((float) ((-height) + getPaddingTop()), this.f241s * ((float) width));
                this.f218Q.m462a(height, width);
                i = 0 | this.f218Q.m465a(canvas);
                canvas.restoreToCount(a);
            }
            if (!this.f219R.m463a()) {
                a = canvas.save();
                height = getWidth();
                width = (getHeight() - getPaddingTop()) - getPaddingBottom();
                canvas.rotate(90.0f);
                canvas.translate((float) (-getPaddingTop()), (-(this.f242t + 1.0f)) * ((float) height));
                this.f219R.m462a(width, height);
                i |= this.f219R.m465a(canvas);
                canvas.restoreToCount(a);
            }
        } else {
            this.f218Q.m466b();
            this.f219R.m466b();
        }
        if (i != 0) {
            C0061x.m385b(this);
        }
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        Drawable drawable = this.f238p;
        if (drawable != null && drawable.isStateful()) {
            drawable.setState(getDrawableState());
        }
    }

    protected LayoutParams generateDefaultLayoutParams() {
        return new aq();
    }

    public LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new aq(getContext(), attributeSet);
    }

    protected LayoutParams generateLayoutParams(LayoutParams layoutParams) {
        return generateDefaultLayoutParams();
    }

    public C0055r getAdapter() {
        return this.f230h;
    }

    protected int getChildDrawingOrder(int i, int i2) {
        if (this.ad == 2) {
            i2 = (i - 1) - i2;
        }
        return ((aq) ((View) this.ae.get(i2)).getLayoutParams()).f260f;
    }

    public int getCurrentItem() {
        return this.f231i;
    }

    public int getOffscreenPageLimit() {
        return this.f248z;
    }

    public int getPageMargin() {
        return this.f237o;
    }

    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f220S = true;
    }

    protected void onDetachedFromWindow() {
        removeCallbacks(this.ag);
        super.onDetachedFromWindow();
    }

    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.f237o > 0 && this.f238p != null && this.f227e.size() > 0 && this.f230h != null) {
            int scrollX = getScrollX();
            int width = getWidth();
            float f = ((float) this.f237o) / ((float) width);
            ap apVar = (ap) this.f227e.get(0);
            float f2 = apVar.f254e;
            int size = this.f227e.size();
            int i = apVar.f251b;
            int i2 = ((ap) this.f227e.get(size - 1)).f251b;
            int i3 = 0;
            int i4 = i;
            while (i4 < i2) {
                float f3;
                while (i4 > apVar.f251b && i3 < size) {
                    i3++;
                    apVar = (ap) this.f227e.get(i3);
                }
                if (i4 == apVar.f251b) {
                    f3 = (apVar.f254e + apVar.f253d) * ((float) width);
                    f2 = (apVar.f254e + apVar.f253d) + f;
                } else {
                    float a = this.f230h.m351a(i4);
                    f3 = (f2 + a) * ((float) width);
                    f2 += a + f;
                }
                if (((float) this.f237o) + f3 > ((float) scrollX)) {
                    this.f238p.setBounds((int) f3, this.f239q, (int) ((((float) this.f237o) + f3) + 0.5f), this.f240r);
                    this.f238p.draw(canvas);
                }
                if (f3 <= ((float) (scrollX + width))) {
                    i4++;
                } else {
                    return;
                }
            }
        }
    }

    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        int action = motionEvent.getAction() & 255;
        if (action == 3 || action == 1) {
            this.f202A = false;
            this.f203B = false;
            this.f211J = -1;
            if (this.f212K == null) {
                return false;
            }
            this.f212K.recycle();
            this.f212K = null;
            return false;
        }
        if (action != 0) {
            if (this.f202A) {
                return true;
            }
            if (this.f203B) {
                return false;
            }
        }
        switch (action) {
            case 0:
                float x = motionEvent.getX();
                this.f209H = x;
                this.f207F = x;
                x = motionEvent.getY();
                this.f210I = x;
                this.f208G = x;
                this.f211J = C0050m.m327b(motionEvent, 0);
                this.f203B = false;
                this.f235m.computeScrollOffset();
                if (this.ah == 2 && Math.abs(this.f235m.getFinalX() - this.f235m.getCurrX()) > this.f216O) {
                    this.f235m.abortAnimation();
                    this.f247y = false;
                    m241b();
                    this.f202A = true;
                    setScrollState(1);
                    break;
                }
                m217a(false);
                this.f202A = false;
                break;
                break;
            case 2:
                action = this.f211J;
                if (action != -1) {
                    action = C0050m.m325a(motionEvent, action);
                    float c = C0050m.m328c(motionEvent, action);
                    float f = c - this.f207F;
                    float abs = Math.abs(f);
                    float d = C0050m.m330d(motionEvent, action);
                    float abs2 = Math.abs(d - this.f210I);
                    if (f == 0.0f || m218a(this.f207F, f) || !m238a(this, false, (int) f, (int) c, (int) d)) {
                        if (abs > ((float) this.f206E) && 0.5f * abs > abs2) {
                            this.f202A = true;
                            setScrollState(1);
                            this.f207F = f > 0.0f ? this.f209H + ((float) this.f206E) : this.f209H - ((float) this.f206E);
                            this.f208G = d;
                            setScrollingCacheEnabled(true);
                        } else if (abs2 > ((float) this.f206E)) {
                            this.f203B = true;
                        }
                        if (this.f202A && m220b(c)) {
                            C0061x.m385b(this);
                            break;
                        }
                    }
                    this.f207F = c;
                    this.f208G = d;
                    this.f203B = true;
                    return false;
                }
                break;
            case 6:
                m216a(motionEvent);
                break;
        }
        if (this.f212K == null) {
            this.f212K = VelocityTracker.obtain();
        }
        this.f212K.addMovement(motionEvent);
        return this.f202A;
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int max;
        int childCount = getChildCount();
        int i5 = i3 - i;
        int i6 = i4 - i2;
        int paddingLeft = getPaddingLeft();
        int paddingTop = getPaddingTop();
        int paddingRight = getPaddingRight();
        int paddingBottom = getPaddingBottom();
        int scrollX = getScrollX();
        int i7 = 0;
        int i8 = 0;
        while (i8 < childCount) {
            aq aqVar;
            int measuredWidth;
            View childAt = getChildAt(i8);
            if (childAt.getVisibility() != 8) {
                aqVar = (aq) childAt.getLayoutParams();
                if (aqVar.f255a) {
                    int i9 = aqVar.f256b & 112;
                    switch (aqVar.f256b & 7) {
                        case 1:
                            max = Math.max((i5 - childAt.getMeasuredWidth()) / 2, paddingLeft);
                            break;
                        case 3:
                            max = paddingLeft;
                            paddingLeft = childAt.getMeasuredWidth() + paddingLeft;
                            break;
                        case 5:
                            measuredWidth = (i5 - paddingRight) - childAt.getMeasuredWidth();
                            paddingRight += childAt.getMeasuredWidth();
                            max = measuredWidth;
                            break;
                        default:
                            max = paddingLeft;
                            break;
                    }
                    int i10;
                    switch (i9) {
                        case 16:
                            measuredWidth = Math.max((i6 - childAt.getMeasuredHeight()) / 2, paddingTop);
                            i10 = paddingBottom;
                            paddingBottom = paddingTop;
                            paddingTop = i10;
                            break;
                        case 48:
                            measuredWidth = childAt.getMeasuredHeight() + paddingTop;
                            i10 = paddingTop;
                            paddingTop = paddingBottom;
                            paddingBottom = measuredWidth;
                            measuredWidth = i10;
                            break;
                        case 80:
                            measuredWidth = (i6 - paddingBottom) - childAt.getMeasuredHeight();
                            i10 = paddingBottom + childAt.getMeasuredHeight();
                            paddingBottom = paddingTop;
                            paddingTop = i10;
                            break;
                        default:
                            measuredWidth = paddingTop;
                            i10 = paddingBottom;
                            paddingBottom = paddingTop;
                            paddingTop = i10;
                            break;
                    }
                    max += scrollX;
                    childAt.layout(max, measuredWidth, childAt.getMeasuredWidth() + max, childAt.getMeasuredHeight() + measuredWidth);
                    measuredWidth = i7 + 1;
                    i7 = paddingBottom;
                    paddingBottom = paddingTop;
                    paddingTop = paddingRight;
                    paddingRight = paddingLeft;
                    i8++;
                    paddingLeft = paddingRight;
                    paddingRight = paddingTop;
                    paddingTop = i7;
                    i7 = measuredWidth;
                }
            }
            measuredWidth = i7;
            i7 = paddingTop;
            paddingTop = paddingRight;
            paddingRight = paddingLeft;
            i8++;
            paddingLeft = paddingRight;
            paddingRight = paddingTop;
            paddingTop = i7;
            i7 = measuredWidth;
        }
        max = (i5 - paddingLeft) - paddingRight;
        for (paddingRight = 0; paddingRight < childCount; paddingRight++) {
            View childAt2 = getChildAt(paddingRight);
            if (childAt2.getVisibility() != 8) {
                aqVar = (aq) childAt2.getLayoutParams();
                if (!aqVar.f255a) {
                    ap a = m229a(childAt2);
                    if (a != null) {
                        i5 = ((int) (a.f254e * ((float) max))) + paddingLeft;
                        if (aqVar.f258d) {
                            aqVar.f258d = false;
                            childAt2.measure(MeasureSpec.makeMeasureSpec((int) (aqVar.f257c * ((float) max)), 1073741824), MeasureSpec.makeMeasureSpec((i6 - paddingTop) - paddingBottom, 1073741824));
                        }
                        childAt2.layout(i5, paddingTop, childAt2.getMeasuredWidth() + i5, childAt2.getMeasuredHeight() + paddingTop);
                    }
                }
            }
        }
        this.f239q = paddingTop;
        this.f240r = i6 - paddingBottom;
        this.f223V = i7;
        if (this.f220S) {
            m214a(this.f231i, false, 0, false);
        }
        this.f220S = false;
    }

    protected void onMeasure(int i, int i2) {
        int i3;
        setMeasuredDimension(getDefaultSize(0, i), getDefaultSize(0, i2));
        int measuredWidth = getMeasuredWidth();
        this.f205D = Math.min(measuredWidth / 10, this.f204C);
        int paddingLeft = (measuredWidth - getPaddingLeft()) - getPaddingRight();
        int measuredHeight = (getMeasuredHeight() - getPaddingTop()) - getPaddingBottom();
        int childCount = getChildCount();
        for (int i4 = 0; i4 < childCount; i4++) {
            aq aqVar;
            int i5;
            View childAt = getChildAt(i4);
            if (childAt.getVisibility() != 8) {
                aqVar = (aq) childAt.getLayoutParams();
                if (aqVar != null && aqVar.f255a) {
                    int i6 = aqVar.f256b & 7;
                    int i7 = aqVar.f256b & 112;
                    i3 = Integer.MIN_VALUE;
                    i5 = Integer.MIN_VALUE;
                    Object obj = (i7 == 48 || i7 == 80) ? 1 : null;
                    Object obj2 = (i6 == 3 || i6 == 5) ? 1 : null;
                    if (obj != null) {
                        i3 = 1073741824;
                    } else if (obj2 != null) {
                        i5 = 1073741824;
                    }
                    if (aqVar.width != -2) {
                        i7 = 1073741824;
                        i3 = aqVar.width != -1 ? aqVar.width : paddingLeft;
                    } else {
                        i7 = i3;
                        i3 = paddingLeft;
                    }
                    if (aqVar.height != -2) {
                        i5 = 1073741824;
                        if (aqVar.height != -1) {
                            measuredWidth = aqVar.height;
                            childAt.measure(MeasureSpec.makeMeasureSpec(i3, i7), MeasureSpec.makeMeasureSpec(measuredWidth, i5));
                            if (obj != null) {
                                measuredHeight -= childAt.getMeasuredHeight();
                            } else if (obj2 != null) {
                                paddingLeft -= childAt.getMeasuredWidth();
                            }
                        }
                    }
                    measuredWidth = measuredHeight;
                    childAt.measure(MeasureSpec.makeMeasureSpec(i3, i7), MeasureSpec.makeMeasureSpec(measuredWidth, i5));
                    if (obj != null) {
                        measuredHeight -= childAt.getMeasuredHeight();
                    } else if (obj2 != null) {
                        paddingLeft -= childAt.getMeasuredWidth();
                    }
                }
            }
        }
        this.f243u = MeasureSpec.makeMeasureSpec(paddingLeft, 1073741824);
        this.f244v = MeasureSpec.makeMeasureSpec(measuredHeight, 1073741824);
        this.f245w = true;
        m241b();
        this.f245w = false;
        i3 = getChildCount();
        for (i5 = 0; i5 < i3; i5++) {
            View childAt2 = getChildAt(i5);
            if (childAt2.getVisibility() != 8) {
                aqVar = (aq) childAt2.getLayoutParams();
                if (aqVar == null || !aqVar.f255a) {
                    childAt2.measure(MeasureSpec.makeMeasureSpec((int) (aqVar.f257c * ((float) paddingLeft)), 1073741824), this.f244v);
                }
            }
        }
    }

    protected boolean onRequestFocusInDescendants(int i, Rect rect) {
        int i2;
        int i3 = -1;
        int childCount = getChildCount();
        if ((i & 2) != 0) {
            i3 = 1;
            i2 = 0;
        } else {
            i2 = childCount - 1;
            childCount = -1;
        }
        while (i2 != childCount) {
            View childAt = getChildAt(i2);
            if (childAt.getVisibility() == 0) {
                ap a = m229a(childAt);
                if (a != null && a.f251b == this.f231i && childAt.requestFocus(i, rect)) {
                    return true;
                }
            }
            i2 += i3;
        }
        return false;
    }

    public void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof SavedState) {
            SavedState savedState = (SavedState) parcelable;
            super.onRestoreInstanceState(savedState.getSuperState());
            if (this.f230h != null) {
                this.f230h.m357a(savedState.f197b, savedState.f198c);
                m235a(savedState.f196a, false, true);
                return;
            }
            this.f232j = savedState.f196a;
            this.f233k = savedState.f197b;
            this.f234l = savedState.f198c;
            return;
        }
        super.onRestoreInstanceState(parcelable);
    }

    public Parcelable onSaveInstanceState() {
        Parcelable savedState = new SavedState(super.onSaveInstanceState());
        savedState.f196a = this.f231i;
        if (this.f230h != null) {
            savedState.f197b = this.f230h.m363b();
        }
        return savedState;
    }

    protected void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        if (i != i3) {
            m213a(i, i3, this.f237o, this.f237o);
        }
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        boolean z = false;
        if (this.f217P) {
            return true;
        }
        if (motionEvent.getAction() == 0 && motionEvent.getEdgeFlags() != 0) {
            return false;
        }
        if (this.f230h == null || this.f230h.m352a() == 0) {
            return false;
        }
        if (this.f212K == null) {
            this.f212K = VelocityTracker.obtain();
        }
        this.f212K.addMovement(motionEvent);
        float x;
        int a;
        switch (motionEvent.getAction() & 255) {
            case 0:
                this.f235m.abortAnimation();
                this.f247y = false;
                m241b();
                this.f202A = true;
                setScrollState(1);
                x = motionEvent.getX();
                this.f209H = x;
                this.f207F = x;
                x = motionEvent.getY();
                this.f210I = x;
                this.f208G = x;
                this.f211J = C0050m.m327b(motionEvent, 0);
                break;
            case 1:
                if (this.f202A) {
                    VelocityTracker velocityTracker = this.f212K;
                    velocityTracker.computeCurrentVelocity(1000, (float) this.f214M);
                    a = (int) C0056s.m369a(velocityTracker, this.f211J);
                    this.f247y = true;
                    int clientWidth = getClientWidth();
                    int scrollX = getScrollX();
                    ap h = m225h();
                    m236a(m211a(h.f251b, ((((float) scrollX) / ((float) clientWidth)) - h.f254e) / h.f253d, a, (int) (C0050m.m328c(motionEvent, C0050m.m325a(motionEvent, this.f211J)) - this.f209H)), true, true, a);
                    this.f211J = -1;
                    m226i();
                    z = this.f219R.m467c() | this.f218Q.m467c();
                    break;
                }
                break;
            case 2:
                if (!this.f202A) {
                    a = C0050m.m325a(motionEvent, this.f211J);
                    float c = C0050m.m328c(motionEvent, a);
                    float abs = Math.abs(c - this.f207F);
                    float d = C0050m.m330d(motionEvent, a);
                    x = Math.abs(d - this.f208G);
                    if (abs > ((float) this.f206E) && abs > x) {
                        this.f202A = true;
                        this.f207F = c - this.f209H > 0.0f ? this.f209H + ((float) this.f206E) : this.f209H - ((float) this.f206E);
                        this.f208G = d;
                        setScrollState(1);
                        setScrollingCacheEnabled(true);
                    }
                }
                if (this.f202A) {
                    z = false | m220b(C0050m.m328c(motionEvent, C0050m.m325a(motionEvent, this.f211J)));
                    break;
                }
                break;
            case 3:
                if (this.f202A) {
                    m214a(this.f231i, true, 0, false);
                    this.f211J = -1;
                    m226i();
                    z = this.f219R.m467c() | this.f218Q.m467c();
                    break;
                }
                break;
            case 5:
                a = C0050m.m326b(motionEvent);
                this.f207F = C0050m.m328c(motionEvent, a);
                this.f211J = C0050m.m327b(motionEvent, a);
                break;
            case 6:
                m216a(motionEvent);
                this.f207F = C0050m.m328c(motionEvent, C0050m.m325a(motionEvent, this.f211J));
                break;
        }
        if (z) {
            C0061x.m385b(this);
        }
        return true;
    }

    public void removeView(View view) {
        if (this.f245w) {
            removeViewInLayout(view);
        } else {
            super.removeView(view);
        }
    }

    public void setAdapter(C0055r c0055r) {
        if (this.f230h != null) {
            this.f230h.m364b(this.f236n);
            this.f230h.m360a((ViewGroup) this);
            for (int i = 0; i < this.f227e.size(); i++) {
                ap apVar = (ap) this.f227e.get(i);
                this.f230h.m361a((ViewGroup) this, apVar.f251b, apVar.f250a);
            }
            this.f230h.m367b((ViewGroup) this);
            this.f227e.clear();
            m223f();
            this.f231i = 0;
            scrollTo(0, 0);
        }
        C0055r c0055r2 = this.f230h;
        this.f230h = c0055r;
        this.f226b = 0;
        if (this.f230h != null) {
            if (this.f236n == null) {
                this.f236n = new au();
            }
            this.f230h.m356a(this.f236n);
            this.f247y = false;
            boolean z = this.f220S;
            this.f220S = true;
            this.f226b = this.f230h.m352a();
            if (this.f232j >= 0) {
                this.f230h.m357a(this.f233k, this.f234l);
                m235a(this.f232j, false, true);
                this.f232j = -1;
                this.f233k = null;
                this.f234l = null;
            } else if (z) {
                requestLayout();
            } else {
                m241b();
            }
        }
        if (this.aa != null && c0055r2 != c0055r) {
            this.aa.m291a(c0055r2, c0055r);
        }
    }

    void setChildrenDrawingOrderEnabledCompat(boolean z) {
        if (VERSION.SDK_INT >= 7) {
            if (this.ac == null) {
                try {
                    this.ac = ViewGroup.class.getDeclaredMethod("setChildrenDrawingOrderEnabled", new Class[]{Boolean.TYPE});
                } catch (Throwable e) {
                    Log.e("ViewPager", "Can't find setChildrenDrawingOrderEnabled", e);
                }
            }
            try {
                this.ac.invoke(this, new Object[]{Boolean.valueOf(z)});
            } catch (Throwable e2) {
                Log.e("ViewPager", "Error changing children drawing order", e2);
            }
        }
    }

    public void setCurrentItem(int i) {
        this.f247y = false;
        m235a(i, !this.f220S, false);
    }

    public void setOffscreenPageLimit(int i) {
        if (i < 1) {
            Log.w("ViewPager", "Requested offscreen page limit " + i + " too small; defaulting to " + 1);
            i = 1;
        }
        if (i != this.f248z) {
            this.f248z = i;
            m241b();
        }
    }

    void setOnAdapterChangeListener(ar arVar) {
        this.aa = arVar;
    }

    public void setOnPageChangeListener(as asVar) {
        this.f224W = asVar;
    }

    public void setPageMargin(int i) {
        int i2 = this.f237o;
        this.f237o = i;
        int width = getWidth();
        m213a(width, width, i, i2);
        requestLayout();
    }

    public void setPageMarginDrawable(int i) {
        setPageMarginDrawable(getContext().getResources().getDrawable(i));
    }

    public void setPageMarginDrawable(Drawable drawable) {
        this.f238p = drawable;
        if (drawable != null) {
            refreshDrawableState();
        }
        setWillNotDraw(drawable == null);
        invalidate();
    }

    protected boolean verifyDrawable(Drawable drawable) {
        return super.verifyDrawable(drawable) || drawable == this.f238p;
    }
}
