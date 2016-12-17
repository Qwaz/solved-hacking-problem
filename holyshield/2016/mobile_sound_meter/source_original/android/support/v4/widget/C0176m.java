package android.support.v4.widget;

import android.content.Context;
import android.database.Cursor;
import android.database.DataSetObserver;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Filter;
import android.widget.FilterQueryProvider;
import android.widget.Filterable;

/* renamed from: android.support.v4.widget.m */
public abstract class C0176m extends BaseAdapter implements C0175r, Filterable {
    protected boolean f531a;
    protected boolean f532b;
    protected Cursor f533c;
    protected Context f534d;
    protected int f535e;
    protected C0189o f536f;
    protected DataSetObserver f537g;
    protected C0191q f538h;
    protected FilterQueryProvider f539i;

    public C0176m(Context context, Cursor cursor, boolean z) {
        m1458a(context, cursor, z ? 1 : 2);
    }

    public Cursor m1455a() {
        return this.f533c;
    }

    public Cursor m1456a(CharSequence charSequence) {
        return this.f539i != null ? this.f539i.runQuery(charSequence) : this.f533c;
    }

    public abstract View m1457a(Context context, Cursor cursor, ViewGroup viewGroup);

    void m1458a(Context context, Cursor cursor, int i) {
        boolean z = true;
        if ((i & 1) == 1) {
            i |= 2;
            this.f532b = true;
        } else {
            this.f532b = false;
        }
        if (cursor == null) {
            z = false;
        }
        this.f533c = cursor;
        this.f531a = z;
        this.f534d = context;
        this.f535e = z ? cursor.getColumnIndexOrThrow("_id") : -1;
        if ((i & 2) == 2) {
            this.f536f = new C0189o(this);
            this.f537g = new C0190p();
        } else {
            this.f536f = null;
            this.f537g = null;
        }
        if (z) {
            if (this.f536f != null) {
                cursor.registerContentObserver(this.f536f);
            }
            if (this.f537g != null) {
                cursor.registerDataSetObserver(this.f537g);
            }
        }
    }

    public void m1459a(Cursor cursor) {
        Cursor b = m1461b(cursor);
        if (b != null) {
            b.close();
        }
    }

    public abstract void m1460a(View view, Context context, Cursor cursor);

    public Cursor m1461b(Cursor cursor) {
        if (cursor == this.f533c) {
            return null;
        }
        Cursor cursor2 = this.f533c;
        if (cursor2 != null) {
            if (this.f536f != null) {
                cursor2.unregisterContentObserver(this.f536f);
            }
            if (this.f537g != null) {
                cursor2.unregisterDataSetObserver(this.f537g);
            }
        }
        this.f533c = cursor;
        if (cursor != null) {
            if (this.f536f != null) {
                cursor.registerContentObserver(this.f536f);
            }
            if (this.f537g != null) {
                cursor.registerDataSetObserver(this.f537g);
            }
            this.f535e = cursor.getColumnIndexOrThrow("_id");
            this.f531a = true;
            notifyDataSetChanged();
            return cursor2;
        }
        this.f535e = -1;
        this.f531a = false;
        notifyDataSetInvalidated();
        return cursor2;
    }

    public View m1462b(Context context, Cursor cursor, ViewGroup viewGroup) {
        return m1457a(context, cursor, viewGroup);
    }

    protected void m1463b() {
        if (this.f532b && this.f533c != null && !this.f533c.isClosed()) {
            this.f531a = this.f533c.requery();
        }
    }

    public CharSequence m1464c(Cursor cursor) {
        return cursor == null ? "" : cursor.toString();
    }

    public int getCount() {
        return (!this.f531a || this.f533c == null) ? 0 : this.f533c.getCount();
    }

    public View getDropDownView(int i, View view, ViewGroup viewGroup) {
        if (!this.f531a) {
            return null;
        }
        this.f533c.moveToPosition(i);
        if (view == null) {
            view = m1462b(this.f534d, this.f533c, viewGroup);
        }
        m1460a(view, this.f534d, this.f533c);
        return view;
    }

    public Filter getFilter() {
        if (this.f538h == null) {
            this.f538h = new C0191q(this);
        }
        return this.f538h;
    }

    public Object getItem(int i) {
        if (!this.f531a || this.f533c == null) {
            return null;
        }
        this.f533c.moveToPosition(i);
        return this.f533c;
    }

    public long getItemId(int i) {
        return (this.f531a && this.f533c != null && this.f533c.moveToPosition(i)) ? this.f533c.getLong(this.f535e) : 0;
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        if (!this.f531a) {
            throw new IllegalStateException("this should only be called when the cursor is valid");
        } else if (this.f533c.moveToPosition(i)) {
            if (view == null) {
                view = m1457a(this.f534d, this.f533c, viewGroup);
            }
            m1460a(view, this.f534d, this.f533c);
            return view;
        } else {
            throw new IllegalStateException("couldn't move cursor to position " + i);
        }
    }

    public boolean hasStableIds() {
        return true;
    }
}
