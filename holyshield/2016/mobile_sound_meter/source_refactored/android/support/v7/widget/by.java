package android.support.v7.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.database.DataSetObserver;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Handler;
import android.support.v4.p011f.C0101h;
import android.support.v4.widget.ah;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.util.Log;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.PopupWindow;
import android.widget.PopupWindow.OnDismissListener;
import java.lang.reflect.Method;

public class by {
    private static Method f1369a;
    private static Method f1370c;
    private final cg f1371A;
    private Runnable f1372B;
    private final Handler f1373C;
    private Rect f1374D;
    private boolean f1375E;
    private int f1376F;
    int f1377b;
    private Context f1378d;
    private PopupWindow f1379e;
    private ListAdapter f1380f;
    private cc f1381g;
    private int f1382h;
    private int f1383i;
    private int f1384j;
    private int f1385k;
    private int f1386l;
    private boolean f1387m;
    private int f1388n;
    private boolean f1389o;
    private boolean f1390p;
    private View f1391q;
    private int f1392r;
    private DataSetObserver f1393s;
    private View f1394t;
    private Drawable f1395u;
    private OnItemClickListener f1396v;
    private OnItemSelectedListener f1397w;
    private final ck f1398x;
    private final cj f1399y;
    private final ci f1400z;

    static {
        try {
            f1369a = PopupWindow.class.getDeclaredMethod("setClipToScreenEnabled", new Class[]{Boolean.TYPE});
        } catch (NoSuchMethodException e) {
            Log.i("ListPopupWindow", "Could not find method setClipToScreenEnabled() on PopupWindow. Oh well.");
        }
        try {
            f1370c = PopupWindow.class.getDeclaredMethod("getMaxAvailableHeight", new Class[]{View.class, Integer.TYPE, Boolean.TYPE});
        } catch (NoSuchMethodException e2) {
            Log.i("ListPopupWindow", "Could not find method getMaxAvailableHeight(View, int, boolean) on PopupWindow. Oh well.");
        }
    }

    public by(Context context) {
        this(context, null, C0233b.listPopupWindowStyle);
    }

    public by(Context context, AttributeSet attributeSet, int i) {
        this(context, attributeSet, i, 0);
    }

    public by(Context context, AttributeSet attributeSet, int i, int i2) {
        this.f1382h = -2;
        this.f1383i = -2;
        this.f1386l = 1002;
        this.f1388n = 0;
        this.f1389o = false;
        this.f1390p = false;
        this.f1377b = Integer.MAX_VALUE;
        this.f1392r = 0;
        this.f1398x = new ck();
        this.f1399y = new cj();
        this.f1400z = new ci();
        this.f1371A = new cg();
        this.f1374D = new Rect();
        this.f1378d = context;
        this.f1373C = new Handler(context.getMainLooper());
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.ListPopupWindow, i, i2);
        this.f1384j = obtainStyledAttributes.getDimensionPixelOffset(C0243l.ListPopupWindow_android_dropDownHorizontalOffset, 0);
        this.f1385k = obtainStyledAttributes.getDimensionPixelOffset(C0243l.ListPopupWindow_android_dropDownVerticalOffset, 0);
        if (this.f1385k != 0) {
            this.f1387m = true;
        }
        obtainStyledAttributes.recycle();
        this.f1379e = new az(context, attributeSet, i);
        this.f1379e.setInputMethodMode(1);
        this.f1376F = C0101h.m583a(this.f1378d.getResources().getConfiguration().locale);
    }

    private int m2551a(View view, int i, boolean z) {
        if (f1370c != null) {
            try {
                return ((Integer) f1370c.invoke(this.f1379e, new Object[]{view, Integer.valueOf(i), Boolean.valueOf(z)})).intValue();
            } catch (Exception e) {
                Log.i("ListPopupWindow", "Could not call getMaxAvailableHeightMethod(View, int, boolean) on PopupWindow. Using the public version.");
            }
        }
        return this.f1379e.getMaxAvailableHeight(view, i);
    }

    private void m2553a() {
        if (this.f1391q != null) {
            ViewParent parent = this.f1391q.getParent();
            if (parent instanceof ViewGroup) {
                ((ViewGroup) parent).removeView(this.f1391q);
            }
        }
    }

    private int m2554b() {
        int i;
        int i2;
        int i3;
        int i4;
        boolean z = true;
        LayoutParams layoutParams;
        View view;
        if (this.f1381g == null) {
            Context context = this.f1378d;
            this.f1372B = new ca(this);
            this.f1381g = new cc(context, !this.f1375E);
            if (this.f1395u != null) {
                this.f1381g.setSelector(this.f1395u);
            }
            this.f1381g.setAdapter(this.f1380f);
            this.f1381g.setOnItemClickListener(this.f1396v);
            this.f1381g.setFocusable(true);
            this.f1381g.setFocusableInTouchMode(true);
            this.f1381g.setOnItemSelectedListener(new cb(this));
            this.f1381g.setOnScrollListener(this.f1400z);
            if (this.f1397w != null) {
                this.f1381g.setOnItemSelectedListener(this.f1397w);
            }
            View view2 = this.f1381g;
            View view3 = this.f1391q;
            if (view3 != null) {
                View linearLayout = new LinearLayout(context);
                linearLayout.setOrientation(1);
                ViewGroup.LayoutParams layoutParams2 = new LayoutParams(-1, 0, 1.0f);
                switch (this.f1392r) {
                    case C0243l.View_android_theme /*0*/:
                        linearLayout.addView(view3);
                        linearLayout.addView(view2, layoutParams2);
                        break;
                    case C0243l.View_android_focusable /*1*/:
                        linearLayout.addView(view2, layoutParams2);
                        linearLayout.addView(view3);
                        break;
                    default:
                        Log.e("ListPopupWindow", "Invalid hint position " + this.f1392r);
                        break;
                }
                if (this.f1383i >= 0) {
                    i = this.f1383i;
                    i2 = Integer.MIN_VALUE;
                } else {
                    i2 = 0;
                    i = 0;
                }
                view3.measure(MeasureSpec.makeMeasureSpec(i, i2), 0);
                layoutParams = (LayoutParams) view3.getLayoutParams();
                i2 = layoutParams.bottomMargin + (view3.getMeasuredHeight() + layoutParams.topMargin);
                view = linearLayout;
            } else {
                view = view2;
                i2 = 0;
            }
            this.f1379e.setContentView(view);
            i3 = i2;
        } else {
            ViewGroup viewGroup = (ViewGroup) this.f1379e.getContentView();
            view = this.f1391q;
            if (view != null) {
                layoutParams = (LayoutParams) view.getLayoutParams();
                i3 = layoutParams.bottomMargin + (view.getMeasuredHeight() + layoutParams.topMargin);
            } else {
                i3 = 0;
            }
        }
        Drawable background = this.f1379e.getBackground();
        if (background != null) {
            background.getPadding(this.f1374D);
            i2 = this.f1374D.top + this.f1374D.bottom;
            if (this.f1387m) {
                i4 = i2;
            } else {
                this.f1385k = -this.f1374D.top;
                i4 = i2;
            }
        } else {
            this.f1374D.setEmpty();
            i4 = 0;
        }
        if (this.f1379e.getInputMethodMode() != 2) {
            z = false;
        }
        i = m2551a(m2571e(), this.f1385k, z);
        if (this.f1389o || this.f1382h == -1) {
            return i + i4;
        }
        int makeMeasureSpec;
        switch (this.f1383i) {
            case -2:
                makeMeasureSpec = MeasureSpec.makeMeasureSpec(this.f1378d.getResources().getDisplayMetrics().widthPixels - (this.f1374D.left + this.f1374D.right), Integer.MIN_VALUE);
                break;
            case -1:
                makeMeasureSpec = MeasureSpec.makeMeasureSpec(this.f1378d.getResources().getDisplayMetrics().widthPixels - (this.f1374D.left + this.f1374D.right), 1073741824);
                break;
            default:
                makeMeasureSpec = MeasureSpec.makeMeasureSpec(this.f1383i, 1073741824);
                break;
        }
        i2 = this.f1381g.m2637a(makeMeasureSpec, 0, -1, i - i3, -1);
        if (i2 > 0) {
            i3 += i4;
        }
        return i2 + i3;
    }

    private void m2556b(boolean z) {
        if (f1369a != null) {
            try {
                f1369a.invoke(this.f1379e, new Object[]{Boolean.valueOf(z)});
            } catch (Exception e) {
                Log.i("ListPopupWindow", "Could not call setClipToScreenEnabled() on PopupWindow. Oh well.");
            }
        }
    }

    public void m2559a(int i) {
        this.f1392r = i;
    }

    public void m2560a(Drawable drawable) {
        this.f1379e.setBackgroundDrawable(drawable);
    }

    public void m2561a(View view) {
        this.f1394t = view;
    }

    public void m2562a(OnItemClickListener onItemClickListener) {
        this.f1396v = onItemClickListener;
    }

    public void m2563a(ListAdapter listAdapter) {
        if (this.f1393s == null) {
            this.f1393s = new ch();
        } else if (this.f1380f != null) {
            this.f1380f.unregisterDataSetObserver(this.f1393s);
        }
        this.f1380f = listAdapter;
        if (this.f1380f != null) {
            listAdapter.registerDataSetObserver(this.f1393s);
        }
        if (this.f1381g != null) {
            this.f1381g.setAdapter(this.f1380f);
        }
    }

    public void m2564a(OnDismissListener onDismissListener) {
        this.f1379e.setOnDismissListener(onDismissListener);
    }

    public void m2565a(boolean z) {
        this.f1375E = z;
        this.f1379e.setFocusable(z);
    }

    public void m2566b(int i) {
        this.f1384j = i;
    }

    public void m2567c() {
        boolean z = true;
        boolean z2 = false;
        int i = -1;
        int b = m2554b();
        boolean l = m2582l();
        ah.m1432a(this.f1379e, this.f1386l);
        if (this.f1379e.isShowing()) {
            int i2;
            int width = this.f1383i == -1 ? -1 : this.f1383i == -2 ? m2571e().getWidth() : this.f1383i;
            if (this.f1382h == -1) {
                if (!l) {
                    b = -1;
                }
                if (l) {
                    this.f1379e.setWidth(this.f1383i == -1 ? -1 : 0);
                    this.f1379e.setHeight(0);
                    i2 = b;
                } else {
                    this.f1379e.setWidth(this.f1383i == -1 ? -1 : 0);
                    this.f1379e.setHeight(-1);
                    i2 = b;
                }
            } else {
                i2 = this.f1382h == -2 ? b : this.f1382h;
            }
            PopupWindow popupWindow = this.f1379e;
            if (!(this.f1390p || this.f1389o)) {
                z2 = true;
            }
            popupWindow.setOutsideTouchable(z2);
            popupWindow = this.f1379e;
            View e = m2571e();
            b = this.f1384j;
            int i3 = this.f1385k;
            if (width < 0) {
                width = -1;
            }
            if (i2 >= 0) {
                i = i2;
            }
            popupWindow.update(e, b, i3, width, i);
            return;
        }
        int width2 = this.f1383i == -1 ? -1 : this.f1383i == -2 ? m2571e().getWidth() : this.f1383i;
        if (this.f1382h == -1) {
            b = -1;
        } else if (this.f1382h != -2) {
            b = this.f1382h;
        }
        this.f1379e.setWidth(width2);
        this.f1379e.setHeight(b);
        m2556b(true);
        popupWindow = this.f1379e;
        if (this.f1390p || this.f1389o) {
            z = false;
        }
        popupWindow.setOutsideTouchable(z);
        this.f1379e.setTouchInterceptor(this.f1399y);
        ah.m1433a(this.f1379e, m2571e(), this.f1384j, this.f1385k, this.f1388n);
        this.f1381g.setSelection(-1);
        if (!this.f1375E || this.f1381g.isInTouchMode()) {
            m2580j();
        }
        if (!this.f1375E) {
            this.f1373C.post(this.f1371A);
        }
    }

    public void m2568c(int i) {
        this.f1385k = i;
        this.f1387m = true;
    }

    public Drawable m2569d() {
        return this.f1379e.getBackground();
    }

    public void m2570d(int i) {
        this.f1388n = i;
    }

    public View m2571e() {
        return this.f1394t;
    }

    public void m2572e(int i) {
        this.f1383i = i;
    }

    public int m2573f() {
        return this.f1384j;
    }

    public void m2574f(int i) {
        Drawable background = this.f1379e.getBackground();
        if (background != null) {
            background.getPadding(this.f1374D);
            this.f1383i = (this.f1374D.left + this.f1374D.right) + i;
            return;
        }
        m2572e(i);
    }

    public int m2575g() {
        return !this.f1387m ? 0 : this.f1385k;
    }

    public void m2576g(int i) {
        this.f1379e.setInputMethodMode(i);
    }

    public int m2577h() {
        return this.f1383i;
    }

    public void m2578h(int i) {
        cc ccVar = this.f1381g;
        if (m2581k() && ccVar != null) {
            ccVar.f1437g = false;
            ccVar.setSelection(i);
            if (VERSION.SDK_INT >= 11 && ccVar.getChoiceMode() != 0) {
                ccVar.setItemChecked(i, true);
            }
        }
    }

    public void m2579i() {
        this.f1379e.dismiss();
        m2553a();
        this.f1379e.setContentView(null);
        this.f1381g = null;
        this.f1373C.removeCallbacks(this.f1398x);
    }

    public void m2580j() {
        cc ccVar = this.f1381g;
        if (ccVar != null) {
            ccVar.f1437g = true;
            ccVar.requestLayout();
        }
    }

    public boolean m2581k() {
        return this.f1379e.isShowing();
    }

    public boolean m2582l() {
        return this.f1379e.getInputMethodMode() == 2;
    }

    public ListView m2583m() {
        return this.f1381g;
    }
}
