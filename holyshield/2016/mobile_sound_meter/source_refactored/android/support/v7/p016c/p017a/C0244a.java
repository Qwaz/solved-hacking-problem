package android.support.v7.p016c.p017a;

import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.PorterDuff.Mode;
import android.graphics.Rect;
import android.graphics.Region;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.Drawable.Callback;
import android.support.v4.p006c.p007a.C0062a;

/* renamed from: android.support.v7.c.a.a */
public class C0244a extends Drawable implements Callback {
    private Drawable f845a;

    public C0244a(Drawable drawable) {
        m1985a(drawable);
    }

    public Drawable m1984a() {
        return this.f845a;
    }

    public void m1985a(Drawable drawable) {
        if (this.f845a != null) {
            this.f845a.setCallback(null);
        }
        this.f845a = drawable;
        if (drawable != null) {
            drawable.setCallback(this);
        }
    }

    public void draw(Canvas canvas) {
        this.f845a.draw(canvas);
    }

    public int getChangingConfigurations() {
        return this.f845a.getChangingConfigurations();
    }

    public Drawable getCurrent() {
        return this.f845a.getCurrent();
    }

    public int getIntrinsicHeight() {
        return this.f845a.getIntrinsicHeight();
    }

    public int getIntrinsicWidth() {
        return this.f845a.getIntrinsicWidth();
    }

    public int getMinimumHeight() {
        return this.f845a.getMinimumHeight();
    }

    public int getMinimumWidth() {
        return this.f845a.getMinimumWidth();
    }

    public int getOpacity() {
        return this.f845a.getOpacity();
    }

    public boolean getPadding(Rect rect) {
        return this.f845a.getPadding(rect);
    }

    public int[] getState() {
        return this.f845a.getState();
    }

    public Region getTransparentRegion() {
        return this.f845a.getTransparentRegion();
    }

    public void invalidateDrawable(Drawable drawable) {
        invalidateSelf();
    }

    public boolean isAutoMirrored() {
        return C0062a.m463b(this.f845a);
    }

    public boolean isStateful() {
        return this.f845a.isStateful();
    }

    public void jumpToCurrentState() {
        C0062a.m454a(this.f845a);
    }

    protected void onBoundsChange(Rect rect) {
        this.f845a.setBounds(rect);
    }

    protected boolean onLevelChange(int i) {
        return this.f845a.setLevel(i);
    }

    public void scheduleDrawable(Drawable drawable, Runnable runnable, long j) {
        scheduleSelf(runnable, j);
    }

    public void setAlpha(int i) {
        this.f845a.setAlpha(i);
    }

    public void setAutoMirrored(boolean z) {
        C0062a.m462a(this.f845a, z);
    }

    public void setChangingConfigurations(int i) {
        this.f845a.setChangingConfigurations(i);
    }

    public void setColorFilter(ColorFilter colorFilter) {
        this.f845a.setColorFilter(colorFilter);
    }

    public void setDither(boolean z) {
        this.f845a.setDither(z);
    }

    public void setFilterBitmap(boolean z) {
        this.f845a.setFilterBitmap(z);
    }

    public void setHotspot(float f, float f2) {
        C0062a.m455a(this.f845a, f, f2);
    }

    public void setHotspotBounds(int i, int i2, int i3, int i4) {
        C0062a.m457a(this.f845a, i, i2, i3, i4);
    }

    public boolean setState(int[] iArr) {
        return this.f845a.setState(iArr);
    }

    public void setTint(int i) {
        C0062a.m456a(this.f845a, i);
    }

    public void setTintList(ColorStateList colorStateList) {
        C0062a.m458a(this.f845a, colorStateList);
    }

    public void setTintMode(Mode mode) {
        C0062a.m461a(this.f845a, mode);
    }

    public boolean setVisible(boolean z, boolean z2) {
        return super.setVisible(z, z2) || this.f845a.setVisible(z, z2);
    }

    public void unscheduleDrawable(Drawable drawable, Runnable runnable) {
        unscheduleSelf(runnable);
    }
}
