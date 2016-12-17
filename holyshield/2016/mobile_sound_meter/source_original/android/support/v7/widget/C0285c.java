package android.support.v7.widget;

import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.drawable.Drawable;

/* renamed from: android.support.v7.widget.c */
class C0285c extends Drawable {
    final ActionBarContainer f1425a;

    public C0285c(ActionBarContainer actionBarContainer) {
        this.f1425a = actionBarContainer;
    }

    public void draw(Canvas canvas) {
        if (!this.f1425a.f1079d) {
            if (this.f1425a.f1076a != null) {
                this.f1425a.f1076a.draw(canvas);
            }
            if (this.f1425a.f1077b != null && this.f1425a.f1080e) {
                this.f1425a.f1077b.draw(canvas);
            }
        } else if (this.f1425a.f1078c != null) {
            this.f1425a.f1078c.draw(canvas);
        }
    }

    public int getOpacity() {
        return 0;
    }

    public void setAlpha(int i) {
    }

    public void setColorFilter(ColorFilter colorFilter) {
    }
}
