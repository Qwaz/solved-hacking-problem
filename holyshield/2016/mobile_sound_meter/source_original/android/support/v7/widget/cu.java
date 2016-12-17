package android.support.v7.widget;

import android.os.ResultReceiver;
import android.view.inputmethod.InputMethodManager;
import android.widget.AutoCompleteTextView;
import java.lang.reflect.Method;

class cu {
    private Method f1479a;
    private Method f1480b;
    private Method f1481c;
    private Method f1482d;

    cu() {
        try {
            this.f1479a = AutoCompleteTextView.class.getDeclaredMethod("doBeforeTextChanged", new Class[0]);
            this.f1479a.setAccessible(true);
        } catch (NoSuchMethodException e) {
        }
        try {
            this.f1480b = AutoCompleteTextView.class.getDeclaredMethod("doAfterTextChanged", new Class[0]);
            this.f1480b.setAccessible(true);
        } catch (NoSuchMethodException e2) {
        }
        try {
            this.f1481c = AutoCompleteTextView.class.getMethod("ensureImeVisible", new Class[]{Boolean.TYPE});
            this.f1481c.setAccessible(true);
        } catch (NoSuchMethodException e3) {
        }
        try {
            this.f1482d = InputMethodManager.class.getMethod("showSoftInputUnchecked", new Class[]{Integer.TYPE, ResultReceiver.class});
            this.f1482d.setAccessible(true);
        } catch (NoSuchMethodException e4) {
        }
    }

    void m2670a(AutoCompleteTextView autoCompleteTextView) {
        if (this.f1479a != null) {
            try {
                this.f1479a.invoke(autoCompleteTextView, new Object[0]);
            } catch (Exception e) {
            }
        }
    }

    void m2671a(AutoCompleteTextView autoCompleteTextView, boolean z) {
        if (this.f1481c != null) {
            try {
                this.f1481c.invoke(autoCompleteTextView, new Object[]{Boolean.valueOf(z)});
            } catch (Exception e) {
            }
        }
    }

    void m2672b(AutoCompleteTextView autoCompleteTextView) {
        if (this.f1480b != null) {
            try {
                this.f1480b.invoke(autoCompleteTextView, new Object[0]);
            } catch (Exception e) {
            }
        }
    }
}
