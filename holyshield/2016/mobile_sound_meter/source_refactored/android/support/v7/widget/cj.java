package android.support.v7.widget;

import android.view.MotionEvent;
import android.view.View;
import android.view.View.OnTouchListener;

class cj implements OnTouchListener {
    final /* synthetic */ by f1447a;

    private cj(by byVar) {
        this.f1447a = byVar;
    }

    public boolean onTouch(View view, MotionEvent motionEvent) {
        int action = motionEvent.getAction();
        int x = (int) motionEvent.getX();
        int y = (int) motionEvent.getY();
        if (action == 0 && this.f1447a.f1379e != null && this.f1447a.f1379e.isShowing() && x >= 0 && x < this.f1447a.f1379e.getWidth() && y >= 0 && y < this.f1447a.f1379e.getHeight()) {
            this.f1447a.f1373C.postDelayed(this.f1447a.f1398x, 250);
        } else if (action == 1) {
            this.f1447a.f1373C.removeCallbacks(this.f1447a.f1398x);
        }
        return false;
    }
}
