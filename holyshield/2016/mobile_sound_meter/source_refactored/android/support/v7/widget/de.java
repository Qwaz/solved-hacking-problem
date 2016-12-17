package android.support.v7.widget;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.Resources;
import java.lang.ref.WeakReference;
import java.util.ArrayList;

class de extends ContextWrapper {
    private static final ArrayList f1514a;
    private Resources f1515b;

    static {
        f1514a = new ArrayList();
    }

    private de(Context context) {
        super(context);
    }

    public static Context m2707a(Context context) {
        if (context instanceof de) {
            return context;
        }
        Context context2;
        int size = f1514a.size();
        for (int i = 0; i < size; i++) {
            WeakReference weakReference = (WeakReference) f1514a.get(i);
            context2 = weakReference != null ? (de) weakReference.get() : null;
            if (context2 != null && context2.getBaseContext() == context) {
                return context2;
            }
        }
        context2 = new de(context);
        f1514a.add(new WeakReference(context2));
        return context2;
    }

    public Resources getResources() {
        if (this.f1515b == null) {
            this.f1515b = new dg(this, super.getResources());
        }
        return this.f1515b;
    }
}
