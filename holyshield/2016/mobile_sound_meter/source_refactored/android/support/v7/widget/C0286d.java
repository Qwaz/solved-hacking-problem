package android.support.v7.widget;

import android.graphics.Outline;

/* renamed from: android.support.v7.widget.d */
class C0286d extends C0285c {
    public C0286d(ActionBarContainer actionBarContainer) {
        super(actionBarContainer);
    }

    public void getOutline(Outline outline) {
        if (this.a.f1079d) {
            if (this.a.f1078c != null) {
                this.a.f1078c.getOutline(outline);
            }
        } else if (this.a.f1076a != null) {
            this.a.f1076a.getOutline(outline);
        }
    }
}
