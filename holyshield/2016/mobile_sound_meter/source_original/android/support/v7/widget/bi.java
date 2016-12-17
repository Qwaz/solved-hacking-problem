package android.support.v7.widget;

import android.content.res.Resources.Theme;
import android.database.DataSetObserver;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ListAdapter;
import android.widget.SpinnerAdapter;
import android.widget.ThemedSpinnerAdapter;

class bi implements ListAdapter, SpinnerAdapter {
    private SpinnerAdapter f1367a;
    private ListAdapter f1368b;

    public bi(SpinnerAdapter spinnerAdapter, Theme theme) {
        this.f1367a = spinnerAdapter;
        if (spinnerAdapter instanceof ListAdapter) {
            this.f1368b = (ListAdapter) spinnerAdapter;
        }
        if (theme == null) {
            return;
        }
        if (bg.f1353a && (spinnerAdapter instanceof ThemedSpinnerAdapter)) {
            ThemedSpinnerAdapter themedSpinnerAdapter = (ThemedSpinnerAdapter) spinnerAdapter;
            if (themedSpinnerAdapter.getDropDownViewTheme() != theme) {
                themedSpinnerAdapter.setDropDownViewTheme(theme);
            }
        } else if (spinnerAdapter instanceof dd) {
            dd ddVar = (dd) spinnerAdapter;
            if (ddVar.m2705a() == null) {
                ddVar.m2706a(theme);
            }
        }
    }

    public boolean areAllItemsEnabled() {
        ListAdapter listAdapter = this.f1368b;
        return listAdapter != null ? listAdapter.areAllItemsEnabled() : true;
    }

    public int getCount() {
        return this.f1367a == null ? 0 : this.f1367a.getCount();
    }

    public View getDropDownView(int i, View view, ViewGroup viewGroup) {
        return this.f1367a == null ? null : this.f1367a.getDropDownView(i, view, viewGroup);
    }

    public Object getItem(int i) {
        return this.f1367a == null ? null : this.f1367a.getItem(i);
    }

    public long getItemId(int i) {
        return this.f1367a == null ? -1 : this.f1367a.getItemId(i);
    }

    public int getItemViewType(int i) {
        return 0;
    }

    public View getView(int i, View view, ViewGroup viewGroup) {
        return getDropDownView(i, view, viewGroup);
    }

    public int getViewTypeCount() {
        return 1;
    }

    public boolean hasStableIds() {
        return this.f1367a != null && this.f1367a.hasStableIds();
    }

    public boolean isEmpty() {
        return getCount() == 0;
    }

    public boolean isEnabled(int i) {
        ListAdapter listAdapter = this.f1368b;
        return listAdapter != null ? listAdapter.isEnabled(i) : true;
    }

    public void registerDataSetObserver(DataSetObserver dataSetObserver) {
        if (this.f1367a != null) {
            this.f1367a.registerDataSetObserver(dataSetObserver);
        }
    }

    public void unregisterDataSetObserver(DataSetObserver dataSetObserver) {
        if (this.f1367a != null) {
            this.f1367a.unregisterDataSetObserver(dataSetObserver);
        }
    }
}
