package android.support.v7.view.menu;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0240i;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.ViewGroup.LayoutParams;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.TextView;

public class ListMenuItemView extends LinearLayout implements aa {
    private C0272m f925a;
    private ImageView f926b;
    private RadioButton f927c;
    private TextView f928d;
    private CheckBox f929e;
    private TextView f930f;
    private Drawable f931g;
    private int f932h;
    private Context f933i;
    private boolean f934j;
    private int f935k;
    private Context f936l;
    private LayoutInflater f937m;
    private boolean f938n;

    public ListMenuItemView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public ListMenuItemView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet);
        this.f936l = context;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, C0243l.MenuView, i, 0);
        this.f931g = obtainStyledAttributes.getDrawable(C0243l.MenuView_android_itemBackground);
        this.f932h = obtainStyledAttributes.getResourceId(C0243l.MenuView_android_itemTextAppearance, -1);
        this.f934j = obtainStyledAttributes.getBoolean(C0243l.MenuView_preserveIconSpacing, false);
        this.f933i = context;
        obtainStyledAttributes.recycle();
    }

    private void m2072b() {
        this.f926b = (ImageView) getInflater().inflate(C0240i.abc_list_menu_item_icon, this, false);
        addView(this.f926b, 0);
    }

    private void m2073c() {
        this.f927c = (RadioButton) getInflater().inflate(C0240i.abc_list_menu_item_radio, this, false);
        addView(this.f927c);
    }

    private void m2074d() {
        this.f929e = (CheckBox) getInflater().inflate(C0240i.abc_list_menu_item_checkbox, this, false);
        addView(this.f929e);
    }

    private LayoutInflater getInflater() {
        if (this.f937m == null) {
            this.f937m = LayoutInflater.from(this.f936l);
        }
        return this.f937m;
    }

    public void m2075a(C0272m c0272m, int i) {
        this.f925a = c0272m;
        this.f935k = i;
        setVisibility(c0272m.isVisible() ? 0 : 8);
        setTitle(c0272m.m2217a((aa) this));
        setCheckable(c0272m.isCheckable());
        m2076a(c0272m.m2230f(), c0272m.m2226d());
        setIcon(c0272m.getIcon());
        setEnabled(c0272m.isEnabled());
    }

    public void m2076a(boolean z, char c) {
        int i = (z && this.f925a.m2230f()) ? 0 : 8;
        if (i == 0) {
            this.f930f.setText(this.f925a.m2228e());
        }
        if (this.f930f.getVisibility() != i) {
            this.f930f.setVisibility(i);
        }
    }

    public boolean m2077a() {
        return false;
    }

    public C0272m getItemData() {
        return this.f925a;
    }

    protected void onFinishInflate() {
        super.onFinishInflate();
        setBackgroundDrawable(this.f931g);
        this.f928d = (TextView) findViewById(C0238g.title);
        if (this.f932h != -1) {
            this.f928d.setTextAppearance(this.f933i, this.f932h);
        }
        this.f930f = (TextView) findViewById(C0238g.shortcut);
    }

    protected void onMeasure(int i, int i2) {
        if (this.f926b != null && this.f934j) {
            LayoutParams layoutParams = getLayoutParams();
            LinearLayout.LayoutParams layoutParams2 = (LinearLayout.LayoutParams) this.f926b.getLayoutParams();
            if (layoutParams.height > 0 && layoutParams2.width <= 0) {
                layoutParams2.width = layoutParams.height;
            }
        }
        super.onMeasure(i, i2);
    }

    public void setCheckable(boolean z) {
        if (z || this.f927c != null || this.f929e != null) {
            CompoundButton compoundButton;
            CompoundButton compoundButton2;
            if (this.f925a.m2231g()) {
                if (this.f927c == null) {
                    m2073c();
                }
                compoundButton = this.f927c;
                compoundButton2 = this.f929e;
            } else {
                if (this.f929e == null) {
                    m2074d();
                }
                compoundButton = this.f929e;
                compoundButton2 = this.f927c;
            }
            if (z) {
                compoundButton.setChecked(this.f925a.isChecked());
                int i = z ? 0 : 8;
                if (compoundButton.getVisibility() != i) {
                    compoundButton.setVisibility(i);
                }
                if (compoundButton2 != null && compoundButton2.getVisibility() != 8) {
                    compoundButton2.setVisibility(8);
                    return;
                }
                return;
            }
            if (this.f929e != null) {
                this.f929e.setVisibility(8);
            }
            if (this.f927c != null) {
                this.f927c.setVisibility(8);
            }
        }
    }

    public void setChecked(boolean z) {
        CompoundButton compoundButton;
        if (this.f925a.m2231g()) {
            if (this.f927c == null) {
                m2073c();
            }
            compoundButton = this.f927c;
        } else {
            if (this.f929e == null) {
                m2074d();
            }
            compoundButton = this.f929e;
        }
        compoundButton.setChecked(z);
    }

    public void setForceShowIcon(boolean z) {
        this.f938n = z;
        this.f934j = z;
    }

    public void setIcon(Drawable drawable) {
        int i = (this.f925a.m2233i() || this.f938n) ? 1 : 0;
        if (i == 0 && !this.f934j) {
            return;
        }
        if (this.f926b != null || drawable != null || this.f934j) {
            if (this.f926b == null) {
                m2072b();
            }
            if (drawable != null || this.f934j) {
                ImageView imageView = this.f926b;
                if (i == 0) {
                    drawable = null;
                }
                imageView.setImageDrawable(drawable);
                if (this.f926b.getVisibility() != 0) {
                    this.f926b.setVisibility(0);
                    return;
                }
                return;
            }
            this.f926b.setVisibility(8);
        }
    }

    public void setTitle(CharSequence charSequence) {
        if (charSequence != null) {
            this.f928d.setText(charSequence);
            if (this.f928d.getVisibility() != 0) {
                this.f928d.setVisibility(0);
            }
        } else if (this.f928d.getVisibility() != 8) {
            this.f928d.setVisibility(8);
        }
    }
}
