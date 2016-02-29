package android.support.v4.app;

import android.support.v4.p002c.C0034b;
import android.util.Log;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;

/* renamed from: android.support.v4.app.b */
final class C0004b extends C0003v implements Runnable {
    final C0016n f81a;
    C0005c f82b;
    C0005c f83c;
    int f84d;
    int f85e;
    int f86f;
    int f87g;
    int f88h;
    int f89i;
    int f90j;
    boolean f91k;
    boolean f92l;
    String f93m;
    boolean f94n;
    int f95o;
    int f96p;
    CharSequence f97q;
    int f98r;
    CharSequence f99s;

    public C0004b(C0016n c0016n) {
        this.f92l = true;
        this.f95o = -1;
        this.f81a = c0016n;
    }

    private void m73a(int i, Fragment fragment, String str, int i2) {
        fragment.f51s = this.f81a;
        if (str != null) {
            if (fragment.f57y == null || str.equals(fragment.f57y)) {
                fragment.f57y = str;
            } else {
                throw new IllegalStateException("Can't change tag of fragment " + fragment + ": was " + fragment.f57y + " now " + str);
            }
        }
        if (i != 0) {
            if (fragment.f55w == 0 || fragment.f55w == i) {
                fragment.f55w = i;
                fragment.f56x = i;
            } else {
                throw new IllegalStateException("Can't change container ID of fragment " + fragment + ": was " + fragment.f55w + " now " + i);
            }
        }
        C0005c c0005c = new C0005c();
        c0005c.f102c = i2;
        c0005c.f103d = fragment;
        m79a(c0005c);
    }

    public int m74a() {
        return m75a(false);
    }

    int m75a(boolean z) {
        if (this.f94n) {
            throw new IllegalStateException("commit already called");
        }
        if (C0016n.f132a) {
            Log.v("FragmentManager", "Commit: " + this);
            m80a("  ", null, new PrintWriter(new C0034b("FragmentManager")), null);
        }
        this.f94n = true;
        if (this.f91k) {
            this.f95o = this.f81a.m111a(this);
        } else {
            this.f95o = -1;
        }
        this.f81a.m128a((Runnable) this, z);
        return this.f95o;
    }

    public C0003v m76a(int i, Fragment fragment, String str) {
        m73a(i, fragment, str, 1);
        return this;
    }

    public C0003v m77a(Fragment fragment) {
        C0005c c0005c = new C0005c();
        c0005c.f102c = 6;
        c0005c.f103d = fragment;
        m79a(c0005c);
        return this;
    }

    void m78a(int i) {
        if (this.f91k) {
            if (C0016n.f132a) {
                Log.v("FragmentManager", "Bump nesting in " + this + " by " + i);
            }
            for (C0005c c0005c = this.f82b; c0005c != null; c0005c = c0005c.f100a) {
                Fragment fragment;
                if (c0005c.f103d != null) {
                    fragment = c0005c.f103d;
                    fragment.f50r += i;
                    if (C0016n.f132a) {
                        Log.v("FragmentManager", "Bump nesting of " + c0005c.f103d + " to " + c0005c.f103d.f50r);
                    }
                }
                if (c0005c.f108i != null) {
                    for (int size = c0005c.f108i.size() - 1; size >= 0; size--) {
                        fragment = (Fragment) c0005c.f108i.get(size);
                        fragment.f50r += i;
                        if (C0016n.f132a) {
                            Log.v("FragmentManager", "Bump nesting of " + fragment + " to " + fragment.f50r);
                        }
                    }
                }
            }
        }
    }

    void m79a(C0005c c0005c) {
        if (this.f82b == null) {
            this.f83c = c0005c;
            this.f82b = c0005c;
        } else {
            c0005c.f101b = this.f83c;
            this.f83c.f100a = c0005c;
            this.f83c = c0005c;
        }
        c0005c.f104e = this.f85e;
        c0005c.f105f = this.f86f;
        c0005c.f106g = this.f87g;
        c0005c.f107h = this.f88h;
        this.f84d++;
    }

    public void m80a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        m81a(str, printWriter, true);
    }

    public void m81a(String str, PrintWriter printWriter, boolean z) {
        if (z) {
            printWriter.print(str);
            printWriter.print("mName=");
            printWriter.print(this.f93m);
            printWriter.print(" mIndex=");
            printWriter.print(this.f95o);
            printWriter.print(" mCommitted=");
            printWriter.println(this.f94n);
            if (this.f89i != 0) {
                printWriter.print(str);
                printWriter.print("mTransition=#");
                printWriter.print(Integer.toHexString(this.f89i));
                printWriter.print(" mTransitionStyle=#");
                printWriter.println(Integer.toHexString(this.f90j));
            }
            if (!(this.f85e == 0 && this.f86f == 0)) {
                printWriter.print(str);
                printWriter.print("mEnterAnim=#");
                printWriter.print(Integer.toHexString(this.f85e));
                printWriter.print(" mExitAnim=#");
                printWriter.println(Integer.toHexString(this.f86f));
            }
            if (!(this.f87g == 0 && this.f88h == 0)) {
                printWriter.print(str);
                printWriter.print("mPopEnterAnim=#");
                printWriter.print(Integer.toHexString(this.f87g));
                printWriter.print(" mPopExitAnim=#");
                printWriter.println(Integer.toHexString(this.f88h));
            }
            if (!(this.f96p == 0 && this.f97q == null)) {
                printWriter.print(str);
                printWriter.print("mBreadCrumbTitleRes=#");
                printWriter.print(Integer.toHexString(this.f96p));
                printWriter.print(" mBreadCrumbTitleText=");
                printWriter.println(this.f97q);
            }
            if (!(this.f98r == 0 && this.f99s == null)) {
                printWriter.print(str);
                printWriter.print("mBreadCrumbShortTitleRes=#");
                printWriter.print(Integer.toHexString(this.f98r));
                printWriter.print(" mBreadCrumbShortTitleText=");
                printWriter.println(this.f99s);
            }
        }
        if (this.f82b != null) {
            printWriter.print(str);
            printWriter.println("Operations:");
            String str2 = str + "    ";
            int i = 0;
            C0005c c0005c = this.f82b;
            while (c0005c != null) {
                String str3;
                switch (c0005c.f102c) {
                    case 0:
                        str3 = "NULL";
                        break;
                    case 1:
                        str3 = "ADD";
                        break;
                    case 2:
                        str3 = "REPLACE";
                        break;
                    case 3:
                        str3 = "REMOVE";
                        break;
                    case 4:
                        str3 = "HIDE";
                        break;
                    case 5:
                        str3 = "SHOW";
                        break;
                    case 6:
                        str3 = "DETACH";
                        break;
                    case 7:
                        str3 = "ATTACH";
                        break;
                    default:
                        str3 = "cmd=" + c0005c.f102c;
                        break;
                }
                printWriter.print(str);
                printWriter.print("  Op #");
                printWriter.print(i);
                printWriter.print(": ");
                printWriter.print(str3);
                printWriter.print(" ");
                printWriter.println(c0005c.f103d);
                if (z) {
                    if (!(c0005c.f104e == 0 && c0005c.f105f == 0)) {
                        printWriter.print(str);
                        printWriter.print("enterAnim=#");
                        printWriter.print(Integer.toHexString(c0005c.f104e));
                        printWriter.print(" exitAnim=#");
                        printWriter.println(Integer.toHexString(c0005c.f105f));
                    }
                    if (!(c0005c.f106g == 0 && c0005c.f107h == 0)) {
                        printWriter.print(str);
                        printWriter.print("popEnterAnim=#");
                        printWriter.print(Integer.toHexString(c0005c.f106g));
                        printWriter.print(" popExitAnim=#");
                        printWriter.println(Integer.toHexString(c0005c.f107h));
                    }
                }
                if (c0005c.f108i != null && c0005c.f108i.size() > 0) {
                    for (int i2 = 0; i2 < c0005c.f108i.size(); i2++) {
                        printWriter.print(str2);
                        if (c0005c.f108i.size() == 1) {
                            printWriter.print("Removed: ");
                        } else {
                            if (i2 == 0) {
                                printWriter.println("Removed:");
                            }
                            printWriter.print(str2);
                            printWriter.print("  #");
                            printWriter.print(i2);
                            printWriter.print(": ");
                        }
                        printWriter.println(c0005c.f108i.get(i2));
                    }
                }
                c0005c = c0005c.f100a;
                i++;
            }
        }
    }

    public C0003v m82b(Fragment fragment) {
        C0005c c0005c = new C0005c();
        c0005c.f102c = 7;
        c0005c.f103d = fragment;
        m79a(c0005c);
        return this;
    }

    public String m83b() {
        return this.f93m;
    }

    public void m84b(boolean z) {
        if (C0016n.f132a) {
            Log.v("FragmentManager", "popFromBackStack: " + this);
            m80a("  ", null, new PrintWriter(new C0034b("FragmentManager")), null);
        }
        m78a(-1);
        for (C0005c c0005c = this.f83c; c0005c != null; c0005c = c0005c.f101b) {
            Fragment fragment;
            switch (c0005c.f102c) {
                case 1:
                    fragment = c0005c.f103d;
                    fragment.f24G = c0005c.f107h;
                    this.f81a.m124a(fragment, C0016n.m109c(this.f89i), this.f90j);
                    break;
                case 2:
                    fragment = c0005c.f103d;
                    if (fragment != null) {
                        fragment.f24G = c0005c.f107h;
                        this.f81a.m124a(fragment, C0016n.m109c(this.f89i), this.f90j);
                    }
                    if (c0005c.f108i == null) {
                        break;
                    }
                    for (int i = 0; i < c0005c.f108i.size(); i++) {
                        fragment = (Fragment) c0005c.f108i.get(i);
                        fragment.f24G = c0005c.f106g;
                        this.f81a.m126a(fragment, false);
                    }
                    break;
                case 3:
                    fragment = c0005c.f103d;
                    fragment.f24G = c0005c.f106g;
                    this.f81a.m126a(fragment, false);
                    break;
                case 4:
                    fragment = c0005c.f103d;
                    fragment.f24G = c0005c.f106g;
                    this.f81a.m142c(fragment, C0016n.m109c(this.f89i), this.f90j);
                    break;
                case 5:
                    fragment = c0005c.f103d;
                    fragment.f24G = c0005c.f107h;
                    this.f81a.m136b(fragment, C0016n.m109c(this.f89i), this.f90j);
                    break;
                case 6:
                    fragment = c0005c.f103d;
                    fragment.f24G = c0005c.f106g;
                    this.f81a.m148e(fragment, C0016n.m109c(this.f89i), this.f90j);
                    break;
                case 7:
                    fragment = c0005c.f103d;
                    fragment.f24G = c0005c.f106g;
                    this.f81a.m146d(fragment, C0016n.m109c(this.f89i), this.f90j);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown cmd: " + c0005c.f102c);
            }
        }
        if (z) {
            this.f81a.m117a(this.f81a.f146n, C0016n.m109c(this.f89i), this.f90j, true);
        }
        if (this.f95o >= 0) {
            this.f81a.m134b(this.f95o);
            this.f95o = -1;
        }
    }

    public void run() {
        if (C0016n.f132a) {
            Log.v("FragmentManager", "Run: " + this);
        }
        if (!this.f91k || this.f95o >= 0) {
            m78a(1);
            for (C0005c c0005c = this.f82b; c0005c != null; c0005c = c0005c.f100a) {
                Fragment fragment;
                switch (c0005c.f102c) {
                    case 1:
                        fragment = c0005c.f103d;
                        fragment.f24G = c0005c.f104e;
                        this.f81a.m126a(fragment, false);
                        break;
                    case 2:
                        Fragment fragment2;
                        fragment = c0005c.f103d;
                        if (this.f81a.f139g != null) {
                            fragment2 = fragment;
                            for (int i = 0; i < this.f81a.f139g.size(); i++) {
                                fragment = (Fragment) this.f81a.f139g.get(i);
                                if (C0016n.f132a) {
                                    Log.v("FragmentManager", "OP_REPLACE: adding=" + fragment2 + " old=" + fragment);
                                }
                                if (fragment2 == null || fragment.f56x == fragment2.f56x) {
                                    if (fragment == fragment2) {
                                        fragment2 = null;
                                        c0005c.f103d = null;
                                    } else {
                                        if (c0005c.f108i == null) {
                                            c0005c.f108i = new ArrayList();
                                        }
                                        c0005c.f108i.add(fragment);
                                        fragment.f24G = c0005c.f105f;
                                        if (this.f91k) {
                                            fragment.f50r++;
                                            if (C0016n.f132a) {
                                                Log.v("FragmentManager", "Bump nesting of " + fragment + " to " + fragment.f50r);
                                            }
                                        }
                                        this.f81a.m124a(fragment, this.f89i, this.f90j);
                                    }
                                }
                            }
                        } else {
                            fragment2 = fragment;
                        }
                        if (fragment2 == null) {
                            break;
                        }
                        fragment2.f24G = c0005c.f104e;
                        this.f81a.m126a(fragment2, false);
                        break;
                    case 3:
                        fragment = c0005c.f103d;
                        fragment.f24G = c0005c.f105f;
                        this.f81a.m124a(fragment, this.f89i, this.f90j);
                        break;
                    case 4:
                        fragment = c0005c.f103d;
                        fragment.f24G = c0005c.f105f;
                        this.f81a.m136b(fragment, this.f89i, this.f90j);
                        break;
                    case 5:
                        fragment = c0005c.f103d;
                        fragment.f24G = c0005c.f104e;
                        this.f81a.m142c(fragment, this.f89i, this.f90j);
                        break;
                    case 6:
                        fragment = c0005c.f103d;
                        fragment.f24G = c0005c.f105f;
                        this.f81a.m146d(fragment, this.f89i, this.f90j);
                        break;
                    case 7:
                        fragment = c0005c.f103d;
                        fragment.f24G = c0005c.f104e;
                        this.f81a.m148e(fragment, this.f89i, this.f90j);
                        break;
                    default:
                        throw new IllegalArgumentException("Unknown cmd: " + c0005c.f102c);
                }
            }
            this.f81a.m117a(this.f81a.f146n, this.f89i, this.f90j, true);
            if (this.f91k) {
                this.f81a.m137b(this);
                return;
            }
            return;
        }
        throw new IllegalStateException("addToBackStack() called after commit()");
    }

    public String toString() {
        StringBuilder stringBuilder = new StringBuilder(128);
        stringBuilder.append("BackStackEntry{");
        stringBuilder.append(Integer.toHexString(System.identityHashCode(this)));
        if (this.f95o >= 0) {
            stringBuilder.append(" #");
            stringBuilder.append(this.f95o);
        }
        if (this.f93m != null) {
            stringBuilder.append(" ");
            stringBuilder.append(this.f93m);
        }
        stringBuilder.append("}");
        return stringBuilder.toString();
    }
}
