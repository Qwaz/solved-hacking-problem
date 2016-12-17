package android.support.v4.widget;

import android.database.Cursor;
import android.widget.Filter;
import android.widget.Filter.FilterResults;

/* renamed from: android.support.v4.widget.q */
class C0191q extends Filter {
    C0175r f562a;

    C0191q(C0175r c0175r) {
        this.f562a = c0175r;
    }

    public CharSequence convertResultToString(Object obj) {
        return this.f562a.m1454c((Cursor) obj);
    }

    protected FilterResults performFiltering(CharSequence charSequence) {
        Cursor a = this.f562a.m1452a(charSequence);
        FilterResults filterResults = new FilterResults();
        if (a != null) {
            filterResults.count = a.getCount();
            filterResults.values = a;
        } else {
            filterResults.count = 0;
            filterResults.values = null;
        }
        return filterResults;
    }

    protected void publishResults(CharSequence charSequence, FilterResults filterResults) {
        Cursor a = this.f562a.m1451a();
        if (filterResults.values != null && filterResults.values != a) {
            this.f562a.m1453a((Cursor) filterResults.values);
        }
    }
}
