package android.support.p000a.p001a;

import android.annotation.TargetApi;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.TypedArray;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.drawable.Drawable;
import android.support.v4.p006c.p007a.C0062a;
import android.util.AttributeSet;

@TargetApi(21)
/* renamed from: android.support.a.a.k */
abstract class C0001k extends Drawable {
    Drawable f6a;

    C0001k() {
    }

    static TypedArray m0b(Resources resources, Theme theme, AttributeSet attributeSet, int[] iArr) {
        return theme == null ? resources.obtainAttributes(attributeSet, iArr) : theme.obtainStyledAttributes(attributeSet, iArr, 0, 0);
    }

    public void applyTheme(Theme theme) {
        if (this.f6a != null) {
            C0062a.m459a(this.f6a, theme);
        }
    }

    public void clearColorFilter() {
        if (this.f6a != null) {
            this.f6a.clearColorFilter();
        } else {
            super.clearColorFilter();
        }
    }

    public ColorFilter getColorFilter() {
        return this.f6a != null ? C0062a.m466e(this.f6a) : null;
    }

    public Drawable getCurrent() {
        return this.f6a != null ? this.f6a.getCurrent() : super.getCurrent();
    }

    public int getLayoutDirection() {
        if (this.f6a != null) {
            C0062a.m468g(this.f6a);
        }
        return 0;
    }

    public int getMinimumHeight() {
        return this.f6a != null ? this.f6a.getMinimumHeight() : super.getMinimumHeight();
    }

    public int getMinimumWidth() {
        return this.f6a != null ? this.f6a.getMinimumWidth() : super.getMinimumWidth();
    }

    public boolean getPadding(Rect rect) {
        return this.f6a != null ? this.f6a.getPadding(rect) : super.getPadding(rect);
    }

    public int[] getState() {
        return this.f6a != null ? this.f6a.getState() : super.getState();
    }

    public Region getTransparentRegion() {
        return this.f6a != null ? this.f6a.getTransparentRegion() : super.getTransparentRegion();
    }

    public boolean isAutoMirrored() {
        if (this.f6a != null) {
            C0062a.m463b(this.f6a);
        }
        return false;
    }

    public void jumpToCurrentState() {
        if (this.f6a != null) {
            C0062a.m454a(this.f6a);
        }
    }

    protected void onBoundsChange(Rect rect) {
        if (this.f6a != null) {
            this.f6a.setBounds(rect);
        } else {
            super.onBoundsChange(rect);
        }
    }

    protected boolean onLevelChange(int i) {
        return this.f6a != null ? this.f6a.setLevel(i) : super.onLevelChange(i);
    }

    public void setAutoMirrored(boolean z) {
        if (this.f6a != null) {
            C0062a.m462a(this.f6a, z);
        }
    }

    public void setChangingConfigurations(int i) {
        if (this.f6a != null) {
            this.f6a.setChangingConfigurations(i);
        } else {
            super.setChangingConfigurations(i);
        }
    }

    public void setColorFilter(int i, Mode mode) {
        if (this.f6a != null) {
            this.f6a.setColorFilter(i, mode);
        } else {
            super.setColorFilter(i, mode);
        }
    }

    public void setFilterBitmap(boolean z) {
        if (this.f6a != null) {
            this.f6a.setFilterBitmap(z);
        }
    }

    public void setHotspot(float f, float f2) {
        if (this.f6a != null) {
            C0062a.m455a(this.f6a, f, f2);
        }
    }

    public void setHotspotBounds(int i, int i2, int i3, int i4) {
        if (this.f6a != null) {
            C0062a.m457a(this.f6a, i, i2, i3, i4);
        }
    }

    public boolean setState(int[] iArr) {
        return this.f6a != null ? this.f6a.setState(iArr) : super.setState(iArr);
    }
}
