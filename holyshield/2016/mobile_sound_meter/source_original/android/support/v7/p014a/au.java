package android.support.v7.p014a;

import android.content.Context;
import android.content.ContextWrapper;
import android.view.View;
import android.view.View.OnClickListener;
import java.lang.reflect.Method;

/* renamed from: android.support.v7.a.au */
class au implements OnClickListener {
    private final View f661a;
    private final String f662b;
    private Method f663c;
    private Context f664d;

    public au(View view, String str) {
        this.f661a = view;
        this.f662b = str;
    }

    private void m1790a(Context context, String str) {
        for (Context context2 = context; context2 != null; context2 = context2 instanceof ContextWrapper ? ((ContextWrapper) context2).getBaseContext() : null) {
            try {
                if (!context2.isRestricted()) {
                    Method method = context2.getClass().getMethod(this.f662b, new Class[]{View.class});
                    if (method != null) {
                        this.f663c = method;
                        this.f664d = context2;
                        return;
                    }
                }
            } catch (NoSuchMethodException e) {
            }
        }
        int id = this.f661a.getId();
        throw new IllegalStateException("Could not find method " + this.f662b + "(View) in a parent or ancestor Context for android:onClick " + "attribute defined on view " + this.f661a.getClass() + (id == -1 ? "" : " with id '" + this.f661a.getContext().getResources().getResourceEntryName(id) + "'"));
    }

    public void onClick(View view) {
        if (this.f663c == null) {
            m1790a(this.f661a.getContext(), this.f662b);
        }
        try {
            this.f663c.invoke(this.f664d, new Object[]{view});
        } catch (Throwable e) {
            throw new IllegalStateException("Could not execute non-public method for android:onClick", e);
        } catch (Throwable e2) {
            throw new IllegalStateException("Could not execute method for android:onClick", e2);
        }
    }
}
