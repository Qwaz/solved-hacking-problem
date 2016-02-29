package android.support.v4.app;

import android.app.Activity;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.support.v4.p002c.C0033a;
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
import java.util.HashMap;

public class Fragment implements ComponentCallbacks, OnCreateContextMenuListener {
    private static final HashMap f17P;
    boolean f18A;
    boolean f19B;
    boolean f20C;
    boolean f21D;
    boolean f22E;
    boolean f23F;
    int f24G;
    ViewGroup f25H;
    View f26I;
    View f27J;
    boolean f28K;
    boolean f29L;
    C0026y f30M;
    boolean f31N;
    boolean f32O;
    int f33a;
    View f34b;
    int f35c;
    Bundle f36d;
    SparseArray f37e;
    int f38f;
    String f39g;
    Bundle f40h;
    Fragment f41i;
    int f42j;
    int f43k;
    boolean f44l;
    boolean f45m;
    boolean f46n;
    boolean f47o;
    boolean f48p;
    boolean f49q;
    int f50r;
    C0016n f51s;
    C0011h f52t;
    C0016n f53u;
    Fragment f54v;
    int f55w;
    int f56x;
    String f57y;
    boolean f58z;

    public class SavedState implements Parcelable {
        public static final Creator CREATOR;
        final Bundle f16a;

        static {
            CREATOR = new C0010g();
        }

        SavedState(Parcel parcel, ClassLoader classLoader) {
            this.f16a = parcel.readBundle();
            if (classLoader != null && this.f16a != null) {
                this.f16a.setClassLoader(classLoader);
            }
        }

        public int describeContents() {
            return 0;
        }

        public void writeToParcel(Parcel parcel, int i) {
            parcel.writeBundle(this.f16a);
        }
    }

    static {
        f17P = new HashMap();
    }

    public Fragment() {
        this.f33a = 0;
        this.f38f = -1;
        this.f42j = -1;
        this.f22E = true;
        this.f29L = true;
    }

    public static Fragment m11a(Context context, String str) {
        return m12a(context, str, null);
    }

    public static Fragment m12a(Context context, String str, Bundle bundle) {
        try {
            Class cls = (Class) f17P.get(str);
            if (cls == null) {
                cls = context.getClassLoader().loadClass(str);
                f17P.put(str, cls);
            }
            Fragment fragment = (Fragment) cls.newInstance();
            if (bundle != null) {
                bundle.setClassLoader(fragment.getClass().getClassLoader());
                fragment.f40h = bundle;
            }
            return fragment;
        } catch (Exception e) {
            throw new C0009f("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an" + " empty constructor that is public", e);
        } catch (Exception e2) {
            throw new C0009f("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an" + " empty constructor that is public", e2);
        } catch (Exception e22) {
            throw new C0009f("Unable to instantiate fragment " + str + ": make sure class name exists, is public, and has an" + " empty constructor that is public", e22);
        }
    }

    public View m13a(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        return null;
    }

    public Animation m14a(int i, boolean z, int i2) {
        return null;
    }

    public void m15a(int i, int i2, Intent intent) {
    }

    final void m16a(int i, Fragment fragment) {
        this.f38f = i;
        if (fragment != null) {
            this.f39g = fragment.f39g + ":" + this.f38f;
        } else {
            this.f39g = "android:fragment:" + this.f38f;
        }
    }

    public void m17a(Activity activity) {
        this.f23F = true;
    }

    public void m18a(Activity activity, AttributeSet attributeSet, Bundle bundle) {
        this.f23F = true;
    }

    void m19a(Configuration configuration) {
        onConfigurationChanged(configuration);
        if (this.f53u != null) {
            this.f53u.m120a(configuration);
        }
    }

    final void m20a(Bundle bundle) {
        if (this.f37e != null) {
            this.f27J.restoreHierarchyState(this.f37e);
            this.f37e = null;
        }
        this.f23F = false;
        m43e(bundle);
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onViewStateRestored()");
        }
    }

    public void m21a(Menu menu) {
    }

    public void m22a(Menu menu, MenuInflater menuInflater) {
    }

    public void m23a(View view, Bundle bundle) {
    }

    public void m24a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mFragmentId=#");
        printWriter.print(Integer.toHexString(this.f55w));
        printWriter.print(" mContainerId=#");
        printWriter.print(Integer.toHexString(this.f56x));
        printWriter.print(" mTag=");
        printWriter.println(this.f57y);
        printWriter.print(str);
        printWriter.print("mState=");
        printWriter.print(this.f33a);
        printWriter.print(" mIndex=");
        printWriter.print(this.f38f);
        printWriter.print(" mWho=");
        printWriter.print(this.f39g);
        printWriter.print(" mBackStackNesting=");
        printWriter.println(this.f50r);
        printWriter.print(str);
        printWriter.print("mAdded=");
        printWriter.print(this.f44l);
        printWriter.print(" mRemoving=");
        printWriter.print(this.f45m);
        printWriter.print(" mResumed=");
        printWriter.print(this.f46n);
        printWriter.print(" mFromLayout=");
        printWriter.print(this.f47o);
        printWriter.print(" mInLayout=");
        printWriter.println(this.f48p);
        printWriter.print(str);
        printWriter.print("mHidden=");
        printWriter.print(this.f58z);
        printWriter.print(" mDetached=");
        printWriter.print(this.f18A);
        printWriter.print(" mMenuVisible=");
        printWriter.print(this.f22E);
        printWriter.print(" mHasMenu=");
        printWriter.println(this.f21D);
        printWriter.print(str);
        printWriter.print("mRetainInstance=");
        printWriter.print(this.f19B);
        printWriter.print(" mRetaining=");
        printWriter.print(this.f20C);
        printWriter.print(" mUserVisibleHint=");
        printWriter.println(this.f29L);
        if (this.f51s != null) {
            printWriter.print(str);
            printWriter.print("mFragmentManager=");
            printWriter.println(this.f51s);
        }
        if (this.f52t != null) {
            printWriter.print(str);
            printWriter.print("mActivity=");
            printWriter.println(this.f52t);
        }
        if (this.f54v != null) {
            printWriter.print(str);
            printWriter.print("mParentFragment=");
            printWriter.println(this.f54v);
        }
        if (this.f40h != null) {
            printWriter.print(str);
            printWriter.print("mArguments=");
            printWriter.println(this.f40h);
        }
        if (this.f36d != null) {
            printWriter.print(str);
            printWriter.print("mSavedFragmentState=");
            printWriter.println(this.f36d);
        }
        if (this.f37e != null) {
            printWriter.print(str);
            printWriter.print("mSavedViewState=");
            printWriter.println(this.f37e);
        }
        if (this.f41i != null) {
            printWriter.print(str);
            printWriter.print("mTarget=");
            printWriter.print(this.f41i);
            printWriter.print(" mTargetRequestCode=");
            printWriter.println(this.f43k);
        }
        if (this.f24G != 0) {
            printWriter.print(str);
            printWriter.print("mNextAnim=");
            printWriter.println(this.f24G);
        }
        if (this.f25H != null) {
            printWriter.print(str);
            printWriter.print("mContainer=");
            printWriter.println(this.f25H);
        }
        if (this.f26I != null) {
            printWriter.print(str);
            printWriter.print("mView=");
            printWriter.println(this.f26I);
        }
        if (this.f27J != null) {
            printWriter.print(str);
            printWriter.print("mInnerView=");
            printWriter.println(this.f26I);
        }
        if (this.f34b != null) {
            printWriter.print(str);
            printWriter.print("mAnimatingAway=");
            printWriter.println(this.f34b);
            printWriter.print(str);
            printWriter.print("mStateAfterAnimating=");
            printWriter.println(this.f35c);
        }
        if (this.f30M != null) {
            printWriter.print(str);
            printWriter.println("Loader Manager:");
            this.f30M.m181a(str + "  ", fileDescriptor, printWriter, strArr);
        }
        if (this.f53u != null) {
            printWriter.print(str);
            printWriter.println("Child " + this.f53u + ":");
            this.f53u.m129a(str + "  ", fileDescriptor, printWriter, strArr);
        }
    }

    public void m25a(boolean z) {
    }

    final boolean m26a() {
        return this.f50r > 0;
    }

    public boolean m27a(MenuItem menuItem) {
        return false;
    }

    public final C0011h m28b() {
        return this.f52t;
    }

    public LayoutInflater m29b(Bundle bundle) {
        return this.f52t.getLayoutInflater();
    }

    View m30b(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        if (this.f53u != null) {
            this.f53u.m154i();
        }
        return m13a(layoutInflater, viewGroup, bundle);
    }

    public void m31b(Menu menu) {
    }

    boolean m32b(Menu menu, MenuInflater menuInflater) {
        boolean z = false;
        if (this.f58z) {
            return false;
        }
        if (this.f21D && this.f22E) {
            z = true;
            m22a(menu, menuInflater);
        }
        return this.f53u != null ? z | this.f53u.m132a(menu, menuInflater) : z;
    }

    public boolean m33b(MenuItem menuItem) {
        return false;
    }

    public final Resources m34c() {
        if (this.f52t != null) {
            return this.f52t.getResources();
        }
        throw new IllegalStateException("Fragment " + this + " not attached to Activity");
    }

    public void m35c(Bundle bundle) {
        this.f23F = true;
    }

    boolean m36c(Menu menu) {
        boolean z = false;
        if (this.f58z) {
            return false;
        }
        if (this.f21D && this.f22E) {
            z = true;
            m21a(menu);
        }
        return this.f53u != null ? z | this.f53u.m131a(menu) : z;
    }

    boolean m37c(MenuItem menuItem) {
        if (!this.f58z) {
            if (this.f21D && this.f22E && m27a(menuItem)) {
                return true;
            }
            if (this.f53u != null && this.f53u.m133a(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public void m38d(Bundle bundle) {
        this.f23F = true;
    }

    void m39d(Menu menu) {
        if (!this.f58z) {
            if (this.f21D && this.f22E) {
                m31b(menu);
            }
            if (this.f53u != null) {
                this.f53u.m138b(menu);
            }
        }
    }

    public final boolean m40d() {
        return this.f18A;
    }

    boolean m41d(MenuItem menuItem) {
        if (!this.f58z) {
            if (m33b(menuItem)) {
                return true;
            }
            if (this.f53u != null && this.f53u.m140b(menuItem)) {
                return true;
            }
        }
        return false;
    }

    public void m42e() {
        this.f23F = true;
        if (!this.f31N) {
            this.f31N = true;
            if (!this.f32O) {
                this.f32O = true;
                this.f30M = this.f52t.m93a(this.f39g, this.f31N, false);
            }
            if (this.f30M != null) {
                this.f30M.m183b();
            }
        }
    }

    public void m43e(Bundle bundle) {
        this.f23F = true;
    }

    public final boolean equals(Object obj) {
        return super.equals(obj);
    }

    public void m44f() {
        this.f23F = true;
    }

    public void m45f(Bundle bundle) {
    }

    public void m46g() {
        this.f23F = true;
    }

    void m47g(Bundle bundle) {
        if (this.f53u != null) {
            this.f53u.m154i();
        }
        this.f23F = false;
        m35c(bundle);
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onCreate()");
        } else if (bundle != null) {
            Parcelable parcelable = bundle.getParcelable("android:support:fragments");
            if (parcelable != null) {
                if (this.f53u == null) {
                    m56n();
                }
                this.f53u.m122a(parcelable, null);
                this.f53u.m155j();
            }
        }
    }

    public void m48h() {
        this.f23F = true;
    }

    void m49h(Bundle bundle) {
        if (this.f53u != null) {
            this.f53u.m154i();
        }
        this.f23F = false;
        m38d(bundle);
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onActivityCreated()");
        } else if (this.f53u != null) {
            this.f53u.m156k();
        }
    }

    public final int hashCode() {
        return super.hashCode();
    }

    public void m50i() {
        this.f23F = true;
    }

    void m51i(Bundle bundle) {
        m45f(bundle);
        if (this.f53u != null) {
            Parcelable h = this.f53u.m153h();
            if (h != null) {
                bundle.putParcelable("android:support:fragments", h);
            }
        }
    }

    public void m52j() {
        this.f23F = true;
        if (!this.f32O) {
            this.f32O = true;
            this.f30M = this.f52t.m93a(this.f39g, this.f31N, false);
        }
        if (this.f30M != null) {
            this.f30M.m189h();
        }
    }

    void m53k() {
        this.f38f = -1;
        this.f39g = null;
        this.f44l = false;
        this.f45m = false;
        this.f46n = false;
        this.f47o = false;
        this.f48p = false;
        this.f49q = false;
        this.f50r = 0;
        this.f51s = null;
        this.f52t = null;
        this.f55w = 0;
        this.f56x = 0;
        this.f57y = null;
        this.f58z = false;
        this.f18A = false;
        this.f20C = false;
        this.f30M = null;
        this.f31N = false;
        this.f32O = false;
    }

    public void m54l() {
        this.f23F = true;
    }

    public void m55m() {
    }

    void m56n() {
        this.f53u = new C0016n();
        this.f53u.m127a(this.f52t, new C0008e(this), this);
    }

    void m57o() {
        if (this.f53u != null) {
            this.f53u.m154i();
            this.f53u.m149e();
        }
        this.f23F = false;
        m42e();
        if (this.f23F) {
            if (this.f53u != null) {
                this.f53u.m157l();
            }
            if (this.f30M != null) {
                this.f30M.m188g();
                return;
            }
            return;
        }
        throw new ab("Fragment " + this + " did not call through to super.onStart()");
    }

    public void onConfigurationChanged(Configuration configuration) {
        this.f23F = true;
    }

    public void onCreateContextMenu(ContextMenu contextMenu, View view, ContextMenuInfo contextMenuInfo) {
        m28b().onCreateContextMenu(contextMenu, view, contextMenuInfo);
    }

    public void onLowMemory() {
        this.f23F = true;
    }

    void m58p() {
        if (this.f53u != null) {
            this.f53u.m154i();
            this.f53u.m149e();
        }
        this.f23F = false;
        m44f();
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onResume()");
        } else if (this.f53u != null) {
            this.f53u.m158m();
            this.f53u.m149e();
        }
    }

    void m59q() {
        onLowMemory();
        if (this.f53u != null) {
            this.f53u.m164s();
        }
    }

    void m60r() {
        if (this.f53u != null) {
            this.f53u.m159n();
        }
        this.f23F = false;
        m46g();
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onPause()");
        }
    }

    void m61s() {
        if (this.f53u != null) {
            this.f53u.m160o();
        }
        this.f23F = false;
        m48h();
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onStop()");
        }
    }

    void m62t() {
        if (this.f53u != null) {
            this.f53u.m161p();
        }
        if (this.f31N) {
            this.f31N = false;
            if (!this.f32O) {
                this.f32O = true;
                this.f30M = this.f52t.m93a(this.f39g, this.f31N, false);
            }
            if (this.f30M == null) {
                return;
            }
            if (this.f52t.f117h) {
                this.f30M.m185d();
            } else {
                this.f30M.m184c();
            }
        }
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        C0033a.m202a(this, stringBuilder);
        if (this.f38f >= 0) {
            stringBuilder.append(" #");
            stringBuilder.append(this.f38f);
        }
        if (this.f55w != 0) {
            stringBuilder.append(" id=0x");
            stringBuilder.append(Integer.toHexString(this.f55w));
        }
        if (this.f57y != null) {
            stringBuilder.append(" ");
            stringBuilder.append(this.f57y);
        }
        stringBuilder.append('}');
        return stringBuilder.toString();
    }

    void m63u() {
        if (this.f53u != null) {
            this.f53u.m162q();
        }
        this.f23F = false;
        m50i();
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onDestroyView()");
        } else if (this.f30M != null) {
            this.f30M.m187f();
        }
    }

    void m64v() {
        if (this.f53u != null) {
            this.f53u.m163r();
        }
        this.f23F = false;
        m52j();
        if (!this.f23F) {
            throw new ab("Fragment " + this + " did not call through to super.onDestroy()");
        }
    }
}
