package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v4.p002b.C0020a;
import android.support.v4.p004h.bo;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0240i;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0249e;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup.LayoutParams;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.SpinnerAdapter;

public class bg extends Spinner implements bo {
    private static final boolean f1353a;
    private static final boolean f1354b;
    private static final int[] f1355c;
    private ao f1356d;
    private aj f1357e;
    private Context f1358f;
    private cd f1359g;
    private SpinnerAdapter f1360h;
    private boolean f1361i;
    private bj f1362j;
    private int f1363k;
    private final Rect f1364l;

    static {
        f1353a = VERSION.SDK_INT >= 23;
        f1354b = VERSION.SDK_INT >= 16;
        f1355c = new int[]{16843505};
    }

    public bg(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.spinnerStyle);
    }

    public bg(Context context, AttributeSet attributeSet, int i) {
        this(context, attributeSet, i, -1);
    }

    public bg(Context context, AttributeSet attributeSet, int i, int i2) {
        this(context, attributeSet, i, i2, null);
    }

    public bg(Context context, AttributeSet attributeSet, int i, int i2, Theme theme) {
        Throwable e;
        bj bjVar;
        dh a;
        CharSequence[] e2;
        SpinnerAdapter arrayAdapter;
        super(context, attributeSet, i);
        this.f1364l = new Rect();
        dh a2 = dh.m2710a(context, attributeSet, C0243l.Spinner, i, 0);
        this.f1356d = ao.m2497a();
        this.f1357e = new aj(this, this.f1356d);
        if (theme != null) {
            this.f1358f = new C0249e(context, theme);
        } else {
            int g = a2.m2726g(C0243l.Spinner_popupTheme, 0);
            if (g != 0) {
                this.f1358f = new C0249e(context, g);
            } else {
                this.f1358f = !f1353a ? context : null;
            }
        }
        if (this.f1358f != null) {
            if (i2 == -1) {
                if (VERSION.SDK_INT >= 11) {
                    TypedArray obtainStyledAttributes;
                    try {
                        obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, f1355c, i, 0);
                        try {
                            if (obtainStyledAttributes.hasValue(0)) {
                                i2 = obtainStyledAttributes.getInt(0, 0);
                            }
                            if (obtainStyledAttributes != null) {
                                obtainStyledAttributes.recycle();
                            }
                        } catch (Exception e3) {
                            e = e3;
                            try {
                                Log.i("AppCompatSpinner", "Could not read android:spinnerMode", e);
                                if (obtainStyledAttributes != null) {
                                    obtainStyledAttributes.recycle();
                                }
                                if (i2 == 1) {
                                    bjVar = new bj(this, this.f1358f, attributeSet, i);
                                    a = dh.m2710a(this.f1358f, attributeSet, C0243l.Spinner, i, 0);
                                    this.f1363k = a.m2724f(C0243l.Spinner_android_dropDownWidth, -2);
                                    bjVar.m2560a(a.m2713a(C0243l.Spinner_android_popupBackground));
                                    bjVar.m2590a(a2.m2721d(C0243l.Spinner_android_prompt));
                                    a.m2714a();
                                    this.f1362j = bjVar;
                                    this.f1359g = new bh(this, this, bjVar);
                                }
                                e2 = a2.m2723e(C0243l.Spinner_android_entries);
                                if (e2 != null) {
                                    arrayAdapter = new ArrayAdapter(context, C0240i.support_simple_spinner_dropdown_item, e2);
                                    arrayAdapter.setDropDownViewResource(C0240i.support_simple_spinner_dropdown_item);
                                    setAdapter(arrayAdapter);
                                }
                                a2.m2714a();
                                this.f1361i = true;
                                if (this.f1360h != null) {
                                    setAdapter(this.f1360h);
                                    this.f1360h = null;
                                }
                                this.f1357e.m2479a(attributeSet, i);
                            } catch (Throwable th) {
                                e = th;
                                if (obtainStyledAttributes != null) {
                                    obtainStyledAttributes.recycle();
                                }
                                throw e;
                            }
                        }
                    } catch (Exception e4) {
                        e = e4;
                        obtainStyledAttributes = null;
                        Log.i("AppCompatSpinner", "Could not read android:spinnerMode", e);
                        if (obtainStyledAttributes != null) {
                            obtainStyledAttributes.recycle();
                        }
                        if (i2 == 1) {
                            bjVar = new bj(this, this.f1358f, attributeSet, i);
                            a = dh.m2710a(this.f1358f, attributeSet, C0243l.Spinner, i, 0);
                            this.f1363k = a.m2724f(C0243l.Spinner_android_dropDownWidth, -2);
                            bjVar.m2560a(a.m2713a(C0243l.Spinner_android_popupBackground));
                            bjVar.m2590a(a2.m2721d(C0243l.Spinner_android_prompt));
                            a.m2714a();
                            this.f1362j = bjVar;
                            this.f1359g = new bh(this, this, bjVar);
                        }
                        e2 = a2.m2723e(C0243l.Spinner_android_entries);
                        if (e2 != null) {
                            arrayAdapter = new ArrayAdapter(context, C0240i.support_simple_spinner_dropdown_item, e2);
                            arrayAdapter.setDropDownViewResource(C0240i.support_simple_spinner_dropdown_item);
                            setAdapter(arrayAdapter);
                        }
                        a2.m2714a();
                        this.f1361i = true;
                        if (this.f1360h != null) {
                            setAdapter(this.f1360h);
                            this.f1360h = null;
                        }
                        this.f1357e.m2479a(attributeSet, i);
                    } catch (Throwable th2) {
                        e = th2;
                        obtainStyledAttributes = null;
                        if (obtainStyledAttributes != null) {
                            obtainStyledAttributes.recycle();
                        }
                        throw e;
                    }
                }
                i2 = 1;
            }
            if (i2 == 1) {
                bjVar = new bj(this, this.f1358f, attributeSet, i);
                a = dh.m2710a(this.f1358f, attributeSet, C0243l.Spinner, i, 0);
                this.f1363k = a.m2724f(C0243l.Spinner_android_dropDownWidth, -2);
                bjVar.m2560a(a.m2713a(C0243l.Spinner_android_popupBackground));
                bjVar.m2590a(a2.m2721d(C0243l.Spinner_android_prompt));
                a.m2714a();
                this.f1362j = bjVar;
                this.f1359g = new bh(this, this, bjVar);
            }
        }
        e2 = a2.m2723e(C0243l.Spinner_android_entries);
        if (e2 != null) {
            arrayAdapter = new ArrayAdapter(context, C0240i.support_simple_spinner_dropdown_item, e2);
            arrayAdapter.setDropDownViewResource(C0240i.support_simple_spinner_dropdown_item);
            setAdapter(arrayAdapter);
        }
        a2.m2714a();
        this.f1361i = true;
        if (this.f1360h != null) {
            setAdapter(this.f1360h);
            this.f1360h = null;
        }
        this.f1357e.m2479a(attributeSet, i);
    }

    private int m2544a(SpinnerAdapter spinnerAdapter, Drawable drawable) {
        if (spinnerAdapter == null) {
            return 0;
        }
        int makeMeasureSpec = MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 0);
        int makeMeasureSpec2 = MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 0);
        int max = Math.max(0, getSelectedItemPosition());
        int min = Math.min(spinnerAdapter.getCount(), max + 15);
        int max2 = Math.max(0, max - (15 - (min - max)));
        View view = null;
        int i = 0;
        max = 0;
        while (max2 < min) {
            View view2;
            int itemViewType = spinnerAdapter.getItemViewType(max2);
            if (itemViewType != max) {
                view2 = null;
            } else {
                itemViewType = max;
                view2 = view;
            }
            view = spinnerAdapter.getView(max2, view2, this);
            if (view.getLayoutParams() == null) {
                view.setLayoutParams(new LayoutParams(-2, -2));
            }
            view.measure(makeMeasureSpec, makeMeasureSpec2);
            i = Math.max(i, view.getMeasuredWidth());
            max2++;
            max = itemViewType;
        }
        if (drawable == null) {
            return i;
        }
        drawable.getPadding(this.f1364l);
        return (this.f1364l.left + this.f1364l.right) + i;
    }

    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (this.f1357e != null) {
            this.f1357e.m2482c();
        }
    }

    public int getDropDownHorizontalOffset() {
        return this.f1362j != null ? this.f1362j.m2573f() : f1354b ? super.getDropDownHorizontalOffset() : 0;
    }

    public int getDropDownVerticalOffset() {
        return this.f1362j != null ? this.f1362j.m2575g() : f1354b ? super.getDropDownVerticalOffset() : 0;
    }

    public int getDropDownWidth() {
        return this.f1362j != null ? this.f1363k : f1354b ? super.getDropDownWidth() : 0;
    }

    public Drawable getPopupBackground() {
        return this.f1362j != null ? this.f1362j.m2569d() : f1354b ? super.getPopupBackground() : null;
    }

    public Context getPopupContext() {
        return this.f1362j != null ? this.f1358f : f1353a ? super.getPopupContext() : null;
    }

    public CharSequence getPrompt() {
        return this.f1362j != null ? this.f1362j.m2588a() : super.getPrompt();
    }

    public ColorStateList getSupportBackgroundTintList() {
        return this.f1357e != null ? this.f1357e.m2474a() : null;
    }

    public Mode getSupportBackgroundTintMode() {
        return this.f1357e != null ? this.f1357e.m2480b() : null;
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (this.f1362j != null && this.f1362j.m2581k()) {
            this.f1362j.m2579i();
        }
    }

    protected void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        if (this.f1362j != null && MeasureSpec.getMode(i) == Integer.MIN_VALUE) {
            setMeasuredDimension(Math.min(Math.max(getMeasuredWidth(), m2544a(getAdapter(), getBackground())), MeasureSpec.getSize(i)), getMeasuredHeight());
        }
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        return (this.f1359g == null || !this.f1359g.onTouch(this, motionEvent)) ? super.onTouchEvent(motionEvent) : true;
    }

    public boolean performClick() {
        if (this.f1362j == null) {
            return super.performClick();
        }
        if (!this.f1362j.m2581k()) {
            this.f1362j.m2592c();
        }
        return true;
    }

    public void setAdapter(SpinnerAdapter spinnerAdapter) {
        if (this.f1361i) {
            super.setAdapter(spinnerAdapter);
            if (this.f1362j != null) {
                this.f1362j.m2589a(new bi(spinnerAdapter, (this.f1358f == null ? getContext() : this.f1358f).getTheme()));
                return;
            }
            return;
        }
        this.f1360h = spinnerAdapter;
    }

    public void setBackgroundDrawable(Drawable drawable) {
        super.setBackgroundDrawable(drawable);
        if (this.f1357e != null) {
            this.f1357e.m2478a(drawable);
        }
    }

    public void setBackgroundResource(int i) {
        super.setBackgroundResource(i);
        if (this.f1357e != null) {
            this.f1357e.m2475a(i);
        }
    }

    public void setDropDownHorizontalOffset(int i) {
        if (this.f1362j != null) {
            this.f1362j.m2566b(i);
        } else if (f1354b) {
            super.setDropDownHorizontalOffset(i);
        }
    }

    public void setDropDownVerticalOffset(int i) {
        if (this.f1362j != null) {
            this.f1362j.m2568c(i);
        } else if (f1354b) {
            super.setDropDownVerticalOffset(i);
        }
    }

    public void setDropDownWidth(int i) {
        if (this.f1362j != null) {
            this.f1363k = i;
        } else if (f1354b) {
            super.setDropDownWidth(i);
        }
    }

    public void setPopupBackgroundDrawable(Drawable drawable) {
        if (this.f1362j != null) {
            this.f1362j.m2560a(drawable);
        } else if (f1354b) {
            super.setPopupBackgroundDrawable(drawable);
        }
    }

    public void setPopupBackgroundResource(int i) {
        setPopupBackgroundDrawable(C0020a.m74a(getPopupContext(), i));
    }

    public void setPrompt(CharSequence charSequence) {
        if (this.f1362j != null) {
            this.f1362j.m2590a(charSequence);
        } else {
            super.setPrompt(charSequence);
        }
    }

    public void setSupportBackgroundTintList(ColorStateList colorStateList) {
        if (this.f1357e != null) {
            this.f1357e.m2476a(colorStateList);
        }
    }

    public void setSupportBackgroundTintMode(Mode mode) {
        if (this.f1357e != null) {
            this.f1357e.m2477a(mode);
        }
    }
}
