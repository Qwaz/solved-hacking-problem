package android.support.v4.widget;

import android.widget.ListView;

/* renamed from: android.support.v4.widget.z */
public class C0199z extends C0174a {
    private final ListView f565a;

    public C0199z(ListView listView) {
        super(listView);
        this.f565a = listView;
    }

    public void m1596a(int i, int i2) {
        aa.m1423a(this.f565a, i2);
    }

    public boolean m1597e(int i) {
        return false;
    }

    public boolean m1598f(int i) {
        ListView listView = this.f565a;
        int count = listView.getCount();
        if (count == 0) {
            return false;
        }
        int childCount = listView.getChildCount();
        int firstVisiblePosition = listView.getFirstVisiblePosition();
        int i2 = firstVisiblePosition + childCount;
        if (i > 0) {
            if (i2 >= count && listView.getChildAt(childCount - 1).getBottom() <= listView.getHeight()) {
                return false;
            }
        } else if (i >= 0) {
            return false;
        } else {
            if (firstVisiblePosition <= 0 && listView.getChildAt(0).getTop() >= 0) {
                return false;
            }
        }
        return true;
    }
}
