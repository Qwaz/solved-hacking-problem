package android.support.v4.p004h;

import android.view.View;
import android.view.View.OnApplyWindowInsetsListener;
import android.view.WindowInsets;

/* renamed from: android.support.v4.h.cr */
final class cr implements OnApplyWindowInsetsListener {
    final /* synthetic */ bm f450a;

    cr(bm bmVar) {
        this.f450a = bmVar;
    }

    public WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
        return ((ec) this.f450a.m970a(view, new ec(windowInsets))).m1303e();
    }
}
