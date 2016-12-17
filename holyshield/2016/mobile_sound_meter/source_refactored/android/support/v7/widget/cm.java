package android.support.v7.widget;

import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.support.v7.p016c.p017a.C0244a;

class cm extends C0244a {
    private boolean f1449a;

    public cm(Drawable drawable) {
        super(drawable);
        this.f1449a = true;
    }

    void m2651a(boolean z) {
        this.f1449a = z;
    }

    public void draw(Canvas canvas) {
        if (this.f1449a) {
            super.draw(canvas);
        }
    }

    public void setHotspot(float f, float f2) {
        if (this.f1449a) {
            super.setHotspot(f, f2);
        }
    }

    public void setHotspotBounds(int i, int i2, int i3, int i4) {
        if (this.f1449a) {
            super.setHotspotBounds(i, i2, i3, i4);
        }
    }

    public boolean setState(int[] iArr) {
        return this.f1449a ? super.setState(iArr) : false;
    }

    public boolean setVisible(boolean z, boolean z2) {
        return this.f1449a ? super.setVisible(z, z2) : false;
    }
}
