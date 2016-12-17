package android.support.v7.view;

import android.view.InflateException;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import java.lang.reflect.Method;

/* renamed from: android.support.v7.view.j */
class C0254j implements OnMenuItemClickListener {
    private static final Class[] f870a;
    private Object f871b;
    private Method f872c;

    static {
        f870a = new Class[]{MenuItem.class};
    }

    public C0254j(Object obj, String str) {
        this.f871b = obj;
        Class cls = obj.getClass();
        try {
            this.f872c = cls.getMethod(str, f870a);
        } catch (Throwable e) {
            InflateException inflateException = new InflateException("Couldn't resolve menu item onClick handler " + str + " in class " + cls.getName());
            inflateException.initCause(e);
            throw inflateException;
        }
    }

    public boolean onMenuItemClick(MenuItem menuItem) {
        try {
            if (this.f872c.getReturnType() == Boolean.TYPE) {
                return ((Boolean) this.f872c.invoke(this.f871b, new Object[]{menuItem})).booleanValue();
            }
            this.f872c.invoke(this.f871b, new Object[]{menuItem});
            return true;
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }
}
