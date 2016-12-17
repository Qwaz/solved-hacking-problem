package android.support.v7.p014a;

import android.content.Context;
import android.content.DialogInterface;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Handler;
import android.os.Message;
import android.support.v4.p004h.bu;
import android.support.v4.widget.NestedScrollView;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0243l;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewParent;
import android.view.ViewStub;
import android.view.Window;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.TextView;

/* renamed from: android.support.v7.a.e */
class C0215e {
    private TextView f734A;
    private TextView f735B;
    private View f736C;
    private ListAdapter f737D;
    private int f738E;
    private int f739F;
    private int f740G;
    private int f741H;
    private int f742I;
    private int f743J;
    private int f744K;
    private int f745L;
    private Handler f746M;
    private final OnClickListener f747N;
    private final Context f748a;
    private final as f749b;
    private final Window f750c;
    private CharSequence f751d;
    private CharSequence f752e;
    private ListView f753f;
    private View f754g;
    private int f755h;
    private int f756i;
    private int f757j;
    private int f758k;
    private int f759l;
    private boolean f760m;
    private Button f761n;
    private CharSequence f762o;
    private Message f763p;
    private Button f764q;
    private CharSequence f765r;
    private Message f766s;
    private Button f767t;
    private CharSequence f768u;
    private Message f769v;
    private NestedScrollView f770w;
    private int f771x;
    private Drawable f772y;
    private ImageView f773z;

    public C0215e(Context context, as asVar, Window window) {
        this.f760m = false;
        this.f771x = 0;
        this.f738E = -1;
        this.f745L = 0;
        this.f747N = new C0216f(this);
        this.f748a = context;
        this.f749b = asVar;
        this.f750c = window;
        this.f746M = new C0227q(asVar);
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(null, C0243l.AlertDialog, C0233b.alertDialogStyle, 0);
        this.f739F = obtainStyledAttributes.getResourceId(C0243l.AlertDialog_android_layout, 0);
        this.f740G = obtainStyledAttributes.getResourceId(C0243l.AlertDialog_buttonPanelSideLayout, 0);
        this.f741H = obtainStyledAttributes.getResourceId(C0243l.AlertDialog_listLayout, 0);
        this.f742I = obtainStyledAttributes.getResourceId(C0243l.AlertDialog_multiChoiceItemLayout, 0);
        this.f743J = obtainStyledAttributes.getResourceId(C0243l.AlertDialog_singleChoiceItemLayout, 0);
        this.f744K = obtainStyledAttributes.getResourceId(C0243l.AlertDialog_listItemLayout, 0);
        obtainStyledAttributes.recycle();
        asVar.m1783a(1);
    }

    private ViewGroup m1918a(View view, View view2) {
        if (view == null) {
            return (ViewGroup) (view2 instanceof ViewStub ? ((ViewStub) view2).inflate() : view2);
        }
        if (view2 != null) {
            ViewParent parent = view2.getParent();
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(view2);
            }
        }
        return (ViewGroup) (view instanceof ViewStub ? ((ViewStub) view).inflate() : view);
    }

    private void m1923a(ViewGroup viewGroup) {
        boolean z = false;
        View inflate = this.f754g != null ? this.f754g : this.f755h != 0 ? LayoutInflater.from(this.f748a).inflate(this.f755h, viewGroup, false) : null;
        if (inflate != null) {
            z = true;
        }
        if (!(z && C0215e.m1925a(inflate))) {
            this.f750c.setFlags(131072, 131072);
        }
        if (z) {
            FrameLayout frameLayout = (FrameLayout) this.f750c.findViewById(C0238g.custom);
            frameLayout.addView(inflate, new LayoutParams(-1, -1));
            if (this.f760m) {
                frameLayout.setPadding(this.f756i, this.f757j, this.f758k, this.f759l);
            }
            if (this.f753f != null) {
                ((LinearLayout.LayoutParams) viewGroup.getLayoutParams()).weight = 0.0f;
                return;
            }
            return;
        }
        viewGroup.setVisibility(8);
    }

    private void m1924a(ViewGroup viewGroup, View view, int i, int i2) {
        View view2 = null;
        View findViewById = this.f750c.findViewById(C0238g.scrollIndicatorUp);
        View findViewById2 = this.f750c.findViewById(C0238g.scrollIndicatorDown);
        if (VERSION.SDK_INT >= 23) {
            bu.m980a(view, i, i2);
            if (findViewById != null) {
                viewGroup.removeView(findViewById);
            }
            if (findViewById2 != null) {
                viewGroup.removeView(findViewById2);
                return;
            }
            return;
        }
        if (findViewById != null && (i & 1) == 0) {
            viewGroup.removeView(findViewById);
            findViewById = null;
        }
        if (findViewById2 == null || (i & 2) != 0) {
            view2 = findViewById2;
        } else {
            viewGroup.removeView(findViewById2);
        }
        if (findViewById != null || view2 != null) {
            if (this.f752e != null) {
                this.f770w.setOnScrollChangeListener(new C0217g(this, findViewById, view2));
                this.f770w.post(new C0218h(this, findViewById, view2));
            } else if (this.f753f != null) {
                this.f753f.setOnScrollListener(new C0219i(this, findViewById, view2));
                this.f753f.post(new C0220j(this, findViewById, view2));
            } else {
                if (findViewById != null) {
                    viewGroup.removeView(findViewById);
                }
                if (view2 != null) {
                    viewGroup.removeView(view2);
                }
            }
        }
    }

    static boolean m1925a(View view) {
        if (view.onCheckIsTextEditor()) {
            return true;
        }
        if (!(view instanceof ViewGroup)) {
            return false;
        }
        ViewGroup viewGroup = (ViewGroup) view;
        int childCount = viewGroup.getChildCount();
        while (childCount > 0) {
            childCount--;
            if (C0215e.m1925a(viewGroup.getChildAt(childCount))) {
                return true;
            }
        }
        return false;
    }

    private int m1926b() {
        return this.f740G == 0 ? this.f739F : this.f745L == 1 ? this.f740G : this.f739F;
    }

    private static void m1928b(View view, View view2, View view3) {
        int i = 0;
        if (view2 != null) {
            view2.setVisibility(bu.m989a(view, -1) ? 0 : 4);
        }
        if (view3 != null) {
            if (!bu.m989a(view, 1)) {
                i = 4;
            }
            view3.setVisibility(i);
        }
    }

    private void m1929b(ViewGroup viewGroup) {
        if (this.f736C != null) {
            viewGroup.addView(this.f736C, 0, new LayoutParams(-1, -2));
            this.f750c.findViewById(C0238g.title_template).setVisibility(8);
            return;
        }
        this.f773z = (ImageView) this.f750c.findViewById(16908294);
        if ((!TextUtils.isEmpty(this.f751d) ? 1 : 0) != 0) {
            this.f734A = (TextView) this.f750c.findViewById(C0238g.alertTitle);
            this.f734A.setText(this.f751d);
            if (this.f771x != 0) {
                this.f773z.setImageResource(this.f771x);
                return;
            } else if (this.f772y != null) {
                this.f773z.setImageDrawable(this.f772y);
                return;
            } else {
                this.f734A.setPadding(this.f773z.getPaddingLeft(), this.f773z.getPaddingTop(), this.f773z.getPaddingRight(), this.f773z.getPaddingBottom());
                this.f773z.setVisibility(8);
                return;
            }
        }
        this.f750c.findViewById(C0238g.title_template).setVisibility(8);
        this.f773z.setVisibility(8);
        viewGroup.setVisibility(8);
    }

    private void m1931c() {
        View findViewById = this.f750c.findViewById(C0238g.parentPanel);
        View findViewById2 = findViewById.findViewById(C0238g.topPanel);
        View findViewById3 = findViewById.findViewById(C0238g.contentPanel);
        View findViewById4 = findViewById.findViewById(C0238g.buttonPanel);
        ViewGroup viewGroup = (ViewGroup) findViewById.findViewById(C0238g.customPanel);
        m1923a(viewGroup);
        View findViewById5 = viewGroup.findViewById(C0238g.topPanel);
        View findViewById6 = viewGroup.findViewById(C0238g.contentPanel);
        View findViewById7 = viewGroup.findViewById(C0238g.buttonPanel);
        ViewGroup a = m1918a(findViewById5, findViewById2);
        ViewGroup a2 = m1918a(findViewById6, findViewById3);
        ViewGroup a3 = m1918a(findViewById7, findViewById4);
        m1932c(a2);
        m1934d(a3);
        m1929b(a);
        boolean z = (viewGroup == null || viewGroup.getVisibility() == 8) ? false : true;
        boolean z2 = (a == null || a.getVisibility() == 8) ? false : true;
        boolean z3 = (a3 == null || a3.getVisibility() == 8) ? false : true;
        if (!(z3 || a2 == null)) {
            findViewById3 = a2.findViewById(C0238g.textSpacerNoButtons);
            if (findViewById3 != null) {
                findViewById3.setVisibility(0);
            }
        }
        if (z2 && this.f770w != null) {
            this.f770w.setClipToPadding(true);
        }
        if (!z) {
            findViewById3 = this.f753f != null ? this.f753f : this.f770w;
            if (findViewById3 != null) {
                m1924a(a2, findViewById3, (z3 ? 2 : 0) | (z2 ? 1 : 0), 3);
            }
        }
        ListView listView = this.f753f;
        if (listView != null && this.f737D != null) {
            listView.setAdapter(this.f737D);
            int i = this.f738E;
            if (i > -1) {
                listView.setItemChecked(i, true);
                listView.setSelection(i);
            }
        }
    }

    private void m1932c(ViewGroup viewGroup) {
        this.f770w = (NestedScrollView) this.f750c.findViewById(C0238g.scrollView);
        this.f770w.setFocusable(false);
        this.f770w.setNestedScrollingEnabled(false);
        this.f735B = (TextView) viewGroup.findViewById(16908299);
        if (this.f735B != null) {
            if (this.f752e != null) {
                this.f735B.setText(this.f752e);
                return;
            }
            this.f735B.setVisibility(8);
            this.f770w.removeView(this.f735B);
            if (this.f753f != null) {
                ViewGroup viewGroup2 = (ViewGroup) this.f770w.getParent();
                int indexOfChild = viewGroup2.indexOfChild(this.f770w);
                viewGroup2.removeViewAt(indexOfChild);
                viewGroup2.addView(this.f753f, indexOfChild, new LayoutParams(-1, -1));
                return;
            }
            viewGroup.setVisibility(8);
        }
    }

    private void m1934d(ViewGroup viewGroup) {
        int i;
        int i2 = 1;
        this.f761n = (Button) viewGroup.findViewById(16908313);
        this.f761n.setOnClickListener(this.f747N);
        if (TextUtils.isEmpty(this.f762o)) {
            this.f761n.setVisibility(8);
            i = 0;
        } else {
            this.f761n.setText(this.f762o);
            this.f761n.setVisibility(0);
            i = 1;
        }
        this.f764q = (Button) viewGroup.findViewById(16908314);
        this.f764q.setOnClickListener(this.f747N);
        if (TextUtils.isEmpty(this.f765r)) {
            this.f764q.setVisibility(8);
        } else {
            this.f764q.setText(this.f765r);
            this.f764q.setVisibility(0);
            i |= 2;
        }
        this.f767t = (Button) viewGroup.findViewById(16908315);
        this.f767t.setOnClickListener(this.f747N);
        if (TextUtils.isEmpty(this.f768u)) {
            this.f767t.setVisibility(8);
        } else {
            this.f767t.setText(this.f768u);
            this.f767t.setVisibility(0);
            i |= 4;
        }
        if (i == 0) {
            i2 = 0;
        }
        if (i2 == 0) {
            viewGroup.setVisibility(8);
        }
    }

    public void m1945a() {
        this.f749b.setContentView(m1926b());
        m1931c();
    }

    public void m1946a(int i) {
        this.f754g = null;
        this.f755h = i;
        this.f760m = false;
    }

    public void m1947a(int i, CharSequence charSequence, DialogInterface.OnClickListener onClickListener, Message message) {
        if (message == null && onClickListener != null) {
            message = this.f746M.obtainMessage(i, onClickListener);
        }
        switch (i) {
            case -3:
                this.f768u = charSequence;
                this.f769v = message;
            case -2:
                this.f765r = charSequence;
                this.f766s = message;
            case -1:
                this.f762o = charSequence;
                this.f763p = message;
            default:
                throw new IllegalArgumentException("Button does not exist");
        }
    }

    public void m1948a(Drawable drawable) {
        this.f772y = drawable;
        this.f771x = 0;
        if (this.f773z == null) {
            return;
        }
        if (drawable != null) {
            this.f773z.setVisibility(0);
            this.f773z.setImageDrawable(drawable);
            return;
        }
        this.f773z.setVisibility(8);
    }

    public void m1949a(View view, int i, int i2, int i3, int i4) {
        this.f754g = view;
        this.f755h = 0;
        this.f760m = true;
        this.f756i = i;
        this.f757j = i2;
        this.f758k = i3;
        this.f759l = i4;
    }

    public void m1950a(CharSequence charSequence) {
        this.f751d = charSequence;
        if (this.f734A != null) {
            this.f734A.setText(charSequence);
        }
    }

    public boolean m1951a(int i, KeyEvent keyEvent) {
        return this.f770w != null && this.f770w.m1383a(keyEvent);
    }

    public void m1952b(int i) {
        this.f772y = null;
        this.f771x = i;
        if (this.f773z == null) {
            return;
        }
        if (i != 0) {
            this.f773z.setVisibility(0);
            this.f773z.setImageResource(this.f771x);
            return;
        }
        this.f773z.setVisibility(8);
    }

    public void m1953b(View view) {
        this.f736C = view;
    }

    public void m1954b(CharSequence charSequence) {
        this.f752e = charSequence;
        if (this.f735B != null) {
            this.f735B.setText(charSequence);
        }
    }

    public boolean m1955b(int i, KeyEvent keyEvent) {
        return this.f770w != null && this.f770w.m1383a(keyEvent);
    }

    public int m1956c(int i) {
        TypedValue typedValue = new TypedValue();
        this.f748a.getTheme().resolveAttribute(i, typedValue, true);
        return typedValue.resourceId;
    }

    public void m1957c(View view) {
        this.f754g = view;
        this.f755h = 0;
        this.f760m = false;
    }
}
