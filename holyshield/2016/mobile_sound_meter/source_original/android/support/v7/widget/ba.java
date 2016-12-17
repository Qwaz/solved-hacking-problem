package android.support.v7.widget;

import android.view.ViewTreeObserver.OnScrollChangedListener;
import android.widget.PopupWindow;
import java.lang.ref.WeakReference;
import java.lang.reflect.Field;

final class ba implements OnScrollChangedListener {
    final /* synthetic */ Field f1338a;
    final /* synthetic */ PopupWindow f1339b;
    final /* synthetic */ OnScrollChangedListener f1340c;

    ba(Field field, PopupWindow popupWindow, OnScrollChangedListener onScrollChangedListener) {
        this.f1338a = field;
        this.f1339b = popupWindow;
        this.f1340c = onScrollChangedListener;
    }

    public void onScrollChanged() {
        try {
            WeakReference weakReference = (WeakReference) this.f1338a.get(this.f1339b);
            if (weakReference != null && weakReference.get() != null) {
                this.f1340c.onScrollChanged();
            }
        } catch (IllegalAccessException e) {
        }
    }
}
