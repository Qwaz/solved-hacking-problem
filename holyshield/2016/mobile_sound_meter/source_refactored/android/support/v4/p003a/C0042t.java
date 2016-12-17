package android.support.v4.p003a;

import android.app.Activity;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcelable;
import android.support.v4.p004h.ab;
import android.support.v4.p012g.C0106n;
import android.support.v4.p012g.C0111d;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.ContextMenu;
import android.view.ContextMenu.ContextMenuInfo;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnCreateContextMenuListener;
import android.view.ViewGroup;
import android.view.animation.Animation;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* renamed from: android.support.v4.a.t */
public class C0042t implements ComponentCallbacks, OnCreateContextMenuListener {
    private static final C0106n f265Z;
    static final Object f266a;
    boolean f267A;
    boolean f268B;
    boolean f269C;
    boolean f270D;
    boolean f271E;
    boolean f272F;
    int f273G;
    ViewGroup f274H;
    View f275I;
    View f276J;
    boolean f277K;
    boolean f278L;
    ba f279M;
    boolean f280N;
    boolean f281O;
    Object f282P;
    Object f283Q;
    Object f284R;
    Object f285S;
    Object f286T;
    Object f287U;
    Boolean f288V;
    Boolean f289W;
    bi f290X;
    bi f291Y;
    int f292b;
    View f293c;
    int f294d;
    Bundle f295e;
    SparseArray f296f;
    int f297g;
    String f298h;
    Bundle f299i;
    C0042t f300j;
    int f301k;
    int f302l;
    boolean f303m;
    boolean f304n;
    boolean f305o;
    boolean f306p;
    boolean f307q;
    int f308r;
    af f309s;
    ac f310t;
    af f311u;
    C0042t f312v;
    int f313w;
    int f314x;
    String f315y;
    boolean f316z;

    static {
        f265Z = new C0106n();
        f266a = new Object();
    }

    public C0042t() {
        this.f292b = 0;
        this.f297g = -1;
        this.f301k = -1;
        this.f271E = true;
        this.f278L = true;
        this.f282P = null;
        this.f283Q = f266a;
        this.f284R = null;
        this.f285S = f266a;
        this.f286T = null;
        this.f287U = f266a;
        this.f290X = null;
        this.f291Y = null;
    }

    public static C0042t m339a(Context context, String str) {
        return C0042t.m340a(context, str, null);
    }

    public static C0042t m340a(Context context, String str, Bundle bundle) {
        try {
            Class cls = (Class) f265Z.get(str);
            if (cls == null) {
                cls = context.getClassLoader().loadClass(str);
                f265Z.put(str, cls);
            }
            C0042t c0042t = (C0042t) cls.newInstance();
            if (bundle != null) {
                bundle.setClassLoader(c0042t.getClass().getClassLoader());
                c0042t.f299i = bundle;
            }
            return c0042t;
        } catch (Exception e) {
            throw new C0044v("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an" + " empty constructor that is public", e);
        } catch (Exception e2) {
            throw new C0044v("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an" + " empty constructor that is public", e2);
        } catch (Exception e22) {
            throw new C0044v("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an" + " empty constructor that is public", e22);
        }
    }

    static boolean m341b(Context context, String str) {
        try {
            Class cls = (Class) f265Z.get(str);
            if (cls == null) {
                cls = context.getClassLoader().loadClass(str);
                f265Z.put(str, cls);
            }
            return C0042t.class.isAssignableFrom(cls);
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    void m342A() {
        if (this.f311u != null) {
            this.f311u.m190h();
            this.f311u.m183d();
        }
        this.f292b = 5;
        this.f272F = false;
        m390i();
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onResume()");
        } else if (this.f311u != null) {
            this.f311u.m194l();
            this.f311u.m183d();
        }
    }

    void m343B() {
        onLowMemory();
        if (this.f311u != null) {
            this.f311u.m200r();
        }
    }

    void m344C() {
        if (this.f311u != null) {
            this.f311u.m195m();
        }
        this.f292b = 4;
        this.f272F = false;
        m392j();
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onPause()");
        }
    }

    void m345D() {
        if (this.f311u != null) {
            this.f311u.m196n();
        }
        this.f292b = 3;
        this.f272F = false;
        m393k();
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onStop()");
        }
    }

    void m346E() {
        if (this.f311u != null) {
            this.f311u.m197o();
        }
        this.f292b = 2;
        if (this.f280N) {
            this.f280N = false;
            if (!this.f281O) {
                this.f281O = true;
                this.f279M = this.f310t.m112a(this.f298h, this.f280N, false);
            }
            if (this.f279M == null) {
                return;
            }
            if (this.f310t.m130j()) {
                this.f279M.m243d();
            } else {
                this.f279M.m242c();
            }
        }
    }

    void m347F() {
        if (this.f311u != null) {
            this.f311u.m198p();
        }
        this.f292b = 1;
        this.f272F = false;
        m394l();
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onDestroyView()");
        } else if (this.f279M != null) {
            this.f279M.m245f();
        }
    }

    void m348G() {
        if (this.f311u != null) {
            this.f311u.m199q();
        }
        this.f292b = 0;
        this.f272F = false;
        m395m();
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onDestroy()");
        }
    }

    C0042t m349a(String str) {
        return str.equals(this.f298h) ? this : this.f311u != null ? this.f311u.m171b(str) : null;
    }

    public View m350a(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        return null;
    }

    public Animation m351a(int i, boolean z, int i2) {
        return null;
    }

    public void m352a(int i, int i2, Intent intent) {
    }

    final void m353a(int i, C0042t c0042t) {
        this.f297g = i;
        if (c0042t != null) {
            this.f298h = c0042t.f298h + ":" + this.f297g;
        } else {
            this.f298h = "android:fragment:" + this.f297g;
        }
    }

    public void m354a(int i, String[] strArr, int[] iArr) {
    }

    @Deprecated
    public void m355a(Activity activity) {
        this.f272F = true;
    }

    @Deprecated
    public void m356a(Activity activity, AttributeSet attributeSet, Bundle bundle) {
        this.f272F = true;
    }

    public void m357a(Context context) {
        this.f272F = true;
        Activity f = this.f310t == null ? null : this.f310t.m126f();
        if (f != null) {
            this.f272F = false;
            m355a(f);
        }
    }

    public void m358a(Context context, AttributeSet attributeSet, Bundle bundle) {
        this.f272F = true;
        Activity f = this.f310t == null ? null : this.f310t.m126f();
        if (f != null) {
            this.f272F = false;
            m356a(f, attributeSet, bundle);
        }
    }

    void m359a(Configuration configuration) {
        onConfigurationChanged(configuration);
        if (this.f311u != null) {
            this.f311u.m156a(configuration);
        }
    }

    final void m360a(Bundle bundle) {
        if (this.f296f != null) {
            this.f276J.restoreHierarchyState(this.f296f);
            this.f296f = null;
        }
        this.f272F = false;
        m382e(bundle);
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onViewStateRestored()");
        }
    }

    public void m361a(Menu menu) {
    }

    public void m362a(Menu menu, MenuInflater menuInflater) {
    }

    public void m363a(View view, Bundle bundle) {
    }

    public void m364a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mFragmentId=#");
        printWriter.print(Integer.toHexString(this.f313w));
        printWriter.print(" mContainerId=#");
        printWriter.print(Integer.toHexString(this.f314x));
        printWriter.print(" mTag=");
        printWriter.println(this.f315y);
        printWriter.print(str);
        printWriter.print("mState=");
        printWriter.print(this.f292b);
        printWriter.print(" mIndex=");
        printWriter.print(this.f297g);
        printWriter.print(" mWho=");
        printWriter.print(this.f298h);
        printWriter.print(" mBackStackNesting=");
        printWriter.println(this.f308r);
        printWriter.print(str);
        printWriter.print("mAdded=");
        printWriter.print(this.f303m);
        printWriter.print(" mRemoving=");
        printWriter.print(this.f304n);
        printWriter.print(" mFromLayout=");
        printWriter.print(this.f305o);
        printWriter.print(" mInLayout=");
        printWriter.println(this.f306p);
        printWriter.print(str);
        printWriter.print("mHidden=");
        printWriter.print(this.f316z);
        printWriter.print(" mDetached=");
        printWriter.print(this.f267A);
        printWriter.print(" mMenuVisible=");
        printWriter.print(this.f271E);
        printWriter.print(" mHasMenu=");
        printWriter.println(this.f270D);
        printWriter.print(str);
        printWriter.print("mRetainInstance=");
        printWriter.print(this.f268B);
        printWriter.print(" mRetaining=");
        printWriter.print(this.f269C);
        printWriter.print(" mUserVisibleHint=");
        printWriter.println(this.f278L);
        if (this.f309s != null) {
            printWriter.print(str);
            printWriter.print("mFragmentManager=");
            printWriter.println(this.f309s);
        }
        if (this.f310t != null) {
            printWriter.print(str);
            printWriter.print("mHost=");
            printWriter.println(this.f310t);
        }
        if (this.f312v != null) {
            printWriter.print(str);
            printWriter.print("mParentFragment=");
            printWriter.println(this.f312v);
        }
        if (this.f299i != null) {
            printWriter.print(str);
            printWriter.print("mArguments=");
            printWriter.println(this.f299i);
        }
        if (this.f295e != null) {
            printWriter.print(str);
            printWriter.print("mSavedFragmentState=");
            printWriter.println(this.f295e);
        }
        if (this.f296f != null) {
            printWriter.print(str);
            printWriter.print("mSavedViewState=");
            printWriter.println(this.f296f);
        }
        if (this.f300j != null) {
            printWriter.print(str);
            printWriter.print("mTarget=");
            printWriter.print(this.f300j);
            printWriter.print(" mTargetRequestCode=");
            printWriter.println(this.f302l);
        }
        if (this.f273G != 0) {
            printWriter.print(str);
            printWriter.print("mNextAnim=");
            printWriter.println(this.f273G);
        }
        if (this.f274H != null) {
            printWriter.print(str);
            printWriter.print("mContainer=");
            printWriter.println(this.f274H);
        }
        if (this.f275I != null) {
            printWriter.print(str);
            printWriter.print("mView=");
            printWriter.println(this.f275I);
        }
        if (this.f276J != null) {
            printWriter.print(str);
            printWriter.print("mInnerView=");
            printWriter.println(this.f275I);
        }
        if (this.f293c != null) {
            printWriter.print(str);
            printWriter.print("mAnimatingAway=");
            printWriter.println(this.f293c);
            printWriter.print(str);
            printWriter.print("mStateAfterAnimating=");
            printWriter.println(this.f294d);
        }
        if (this.f279M != null) {
            printWriter.print(str);
            printWriter.println("Loader Manager:");
            this.f279M.m239a(str + "  ", fileDescriptor, printWriter, strArr);
        }
        if (this.f311u != null) {
            printWriter.print(str);
            printWriter.println("Child " + this.f311u + ":");
            this.f311u.m165a(str + "  ", fileDescriptor, printWriter, strArr);
        }
    }

    public void m365a(boolean z) {
    }

    final boolean m366a() {
        return this.f308r > 0;
    }

    public boolean m367a(MenuItem menuItem) {
        return false;
    }

    public final C0045w m368b() {
        return this.f310t == null ? null : (C0045w) this.f310t.m126f();
    }

    public LayoutInflater m369b(Bundle bundle) {
        LayoutInflater b = this.f310t.m120b();
        m378d();
        ab.m838a(b, this.f311u.m201s());
        return b;
    }

    View m370b(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        if (this.f311u != null) {
            this.f311u.m190h();
        }
        return m350a(layoutInflater, viewGroup, bundle);
    }

    public void m371b(Menu menu) {
    }

    boolean m372b(Menu menu, MenuInflater menuInflater) {
        boolean z = false;
        if (this.f316z) {
            return false;
        }
        if (this.f270D && this.f271E) {
            z = true;
            m362a(menu, menuInflater);
        }
        return this.f311u != null ? z | this.f311u.m169a(menu, menuInflater) : z;
    }

    public boolean m373b(MenuItem menuItem) {
        return false;
    }

    public final Resources m374c() {
        if (this.f310t != null) {
            return this.f310t.m127g().getResources();
        }
        throw new IllegalStateException("Fragment " + this + " not attached to Activity");
    }

    public void m375c(Bundle bundle) {
        this.f272F = true;
    }

    boolean m376c(Menu menu) {
        boolean z = false;
        if (this.f316z) {
            return false;
        }
        if (this.f270D && this.f271E) {
            z = true;
            m361a(menu);
        }
        return this.f311u != null ? z | this.f311u.m168a(menu) : z;
    }

    boolean m377c(MenuItem menuItem) {
        if (!this.f316z) {
            if (this.f270D && this.f271E && m367a(menuItem)) {
                return true;
            }
            if (this.f311u != null && this.f311u.m170a(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public final ad m378d() {
        if (this.f311u == null) {
            m407y();
            if (this.f292b >= 5) {
                this.f311u.m194l();
            } else if (this.f292b >= 4) {
                this.f311u.m193k();
            } else if (this.f292b >= 2) {
                this.f311u.m192j();
            } else if (this.f292b >= 1) {
                this.f311u.m191i();
            }
        }
        return this.f311u;
    }

    public void m379d(Bundle bundle) {
        this.f272F = true;
    }

    void m380d(Menu menu) {
        if (!this.f316z) {
            if (this.f270D && this.f271E) {
                m371b(menu);
            }
            if (this.f311u != null) {
                this.f311u.m175b(menu);
            }
        }
    }

    boolean m381d(MenuItem menuItem) {
        if (!this.f316z) {
            if (m373b(menuItem)) {
                return true;
            }
            if (this.f311u != null && this.f311u.m177b(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public void m382e(Bundle bundle) {
        this.f272F = true;
    }

    public final boolean m383e() {
        return this.f310t != null && this.f303m;
    }

    public final boolean equals(Object obj) {
        return super.equals(obj);
    }

    public void m384f(Bundle bundle) {
    }

    public final boolean m385f() {
        return this.f316z;
    }

    public View m386g() {
        return this.f275I;
    }

    void m387g(Bundle bundle) {
        if (this.f311u != null) {
            this.f311u.m190h();
        }
        this.f292b = 1;
        this.f272F = false;
        m375c(bundle);
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onCreate()");
        } else if (bundle != null) {
            Parcelable parcelable = bundle.getParcelable("android:support:fragments");
            if (parcelable != null) {
                if (this.f311u == null) {
                    m407y();
                }
                this.f311u.m158a(parcelable, null);
                this.f311u.m191i();
            }
        }
    }

    public void m388h() {
        this.f272F = true;
        if (!this.f280N) {
            this.f280N = true;
            if (!this.f281O) {
                this.f281O = true;
                this.f279M = this.f310t.m112a(this.f298h, this.f280N, false);
            }
            if (this.f279M != null) {
                this.f279M.m241b();
            }
        }
    }

    void m389h(Bundle bundle) {
        if (this.f311u != null) {
            this.f311u.m190h();
        }
        this.f292b = 2;
        this.f272F = false;
        m379d(bundle);
        if (!this.f272F) {
            throw new bj("Fragment " + this + " did not call through to super.onActivityCreated()");
        } else if (this.f311u != null) {
            this.f311u.m192j();
        }
    }

    public final int hashCode() {
        return super.hashCode();
    }

    public void m390i() {
        this.f272F = true;
    }

    void m391i(Bundle bundle) {
        m384f(bundle);
        if (this.f311u != null) {
            Parcelable g = this.f311u.m189g();
            if (g != null) {
                bundle.putParcelable("android:support:fragments", g);
            }
        }
    }

    public void m392j() {
        this.f272F = true;
    }

    public void m393k() {
        this.f272F = true;
    }

    public void m394l() {
        this.f272F = true;
    }

    public void m395m() {
        this.f272F = true;
        if (!this.f281O) {
            this.f281O = true;
            this.f279M = this.f310t.m112a(this.f298h, this.f280N, false);
        }
        if (this.f279M != null) {
            this.f279M.m247h();
        }
    }

    void m396n() {
        this.f297g = -1;
        this.f298h = null;
        this.f303m = false;
        this.f304n = false;
        this.f305o = false;
        this.f306p = false;
        this.f307q = false;
        this.f308r = 0;
        this.f309s = null;
        this.f311u = null;
        this.f310t = null;
        this.f313w = 0;
        this.f314x = 0;
        this.f315y = null;
        this.f316z = false;
        this.f267A = false;
        this.f269C = false;
        this.f279M = null;
        this.f280N = false;
        this.f281O = false;
    }

    public void m397o() {
        this.f272F = true;
    }

    public void onConfigurationChanged(Configuration configuration) {
        this.f272F = true;
    }

    public void onCreateContextMenu(ContextMenu contextMenu, View view, ContextMenuInfo contextMenuInfo) {
        m368b().onCreateContextMenu(contextMenu, view, contextMenuInfo);
    }

    public void onLowMemory() {
        this.f272F = true;
    }

    public void m398p() {
    }

    public Object m399q() {
        return this.f282P;
    }

    public Object m400r() {
        return this.f283Q == f266a ? m399q() : this.f283Q;
    }

    public Object m401s() {
        return this.f284R;
    }

    public Object m402t() {
        return this.f285S == f266a ? m401s() : this.f285S;
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        C0111d.m636a(this, stringBuilder);
        if (this.f297g >= 0) {
            stringBuilder.append(" #");
            stringBuilder.append(this.f297g);
        }
        if (this.f313w != 0) {
            stringBuilder.append(" id=0x");
            stringBuilder.append(Integer.toHexString(this.f313w));
        }
        if (this.f315y != null) {
            stringBuilder.append(" ");
            stringBuilder.append(this.f315y);
        }
        stringBuilder.append('}');
        return stringBuilder.toString();
    }

    public Object m403u() {
        return this.f286T;
    }

    public Object m404v() {
        return this.f287U == f266a ? m403u() : this.f287U;
    }

    public boolean m405w() {
        return this.f289W == null ? true : this.f289W.booleanValue();
    }

    public boolean m406x() {
        return this.f288V == null ? true : this.f288V.booleanValue();
    }

    void m407y() {
        this.f311u = new af();
        this.f311u.m159a(this.f310t, new C0043u(this), this);
    }

    void m408z() {
        if (this.f311u != null) {
            this.f311u.m190h();
            this.f311u.m183d();
        }
        this.f292b = 4;
        this.f272F = false;
        m388h();
        if (this.f272F) {
            if (this.f311u != null) {
                this.f311u.m193k();
            }
            if (this.f279M != null) {
                this.f279M.m246g();
                return;
            }
            return;
        }
        throw new bj("Fragment " + this + " did not call through to super.onStart()");
    }
}
