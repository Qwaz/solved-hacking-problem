package android.support.v7.widget;

import android.view.ViewTreeObserver;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.widget.PopupWindow.OnDismissListener;

class bm implements OnDismissListener {
    final /* synthetic */ OnGlobalLayoutListener f1408a;
    final /* synthetic */ bj f1409b;

    bm(bj bjVar, OnGlobalLayoutListener onGlobalLayoutListener) {
        this.f1409b = bjVar;
        this.f1408a = onGlobalLayoutListener;
    }

    public void onDismiss() {
        ViewTreeObserver viewTreeObserver = this.f1409b.f1401a.getViewTreeObserver();
        if (viewTreeObserver != null) {
            viewTreeObserver.removeGlobalOnLayoutListener(this.f1408a);
        }
    }
}
