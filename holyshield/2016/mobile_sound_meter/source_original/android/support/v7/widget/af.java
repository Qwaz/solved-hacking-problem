package android.support.v7.widget;

import android.os.AsyncTask;
import android.util.Log;
import android.util.Xml;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import org.xmlpull.v1.XmlSerializer;

final class af extends AsyncTask {
    final /* synthetic */ C0307z f1277a;

    private af(C0307z c0307z) {
        this.f1277a = c0307z;
    }

    public Void m2461a(Object... objArr) {
        int i = 0;
        List list = (List) objArr[0];
        String str = (String) objArr[1];
        try {
            OutputStream openFileOutput = this.f1277a.f1607g.openFileOutput(str, 0);
            XmlSerializer newSerializer = Xml.newSerializer();
            try {
                newSerializer.setOutput(openFileOutput, null);
                newSerializer.startDocument("UTF-8", Boolean.valueOf(true));
                newSerializer.startTag(null, "historical-records");
                int size = list.size();
                while (i < size) {
                    ad adVar = (ad) list.remove(0);
                    newSerializer.startTag(null, "historical-record");
                    newSerializer.attribute(null, "activity", adVar.f1274a.flattenToString());
                    newSerializer.attribute(null, "time", String.valueOf(adVar.f1275b));
                    newSerializer.attribute(null, "weight", String.valueOf(adVar.f1276c));
                    newSerializer.endTag(null, "historical-record");
                    i++;
                }
                newSerializer.endTag(null, "historical-records");
                newSerializer.endDocument();
                this.f1277a.f1612l = true;
                if (openFileOutput != null) {
                    try {
                        openFileOutput.close();
                    } catch (IOException e) {
                    }
                }
            } catch (Throwable e2) {
                Log.e(C0307z.f1601a, "Error writing historical recrod file: " + this.f1277a.f1608h, e2);
                this.f1277a.f1612l = true;
                if (openFileOutput != null) {
                    try {
                        openFileOutput.close();
                    } catch (IOException e3) {
                    }
                }
            } catch (Throwable e22) {
                Log.e(C0307z.f1601a, "Error writing historical recrod file: " + this.f1277a.f1608h, e22);
                this.f1277a.f1612l = true;
                if (openFileOutput != null) {
                    try {
                        openFileOutput.close();
                    } catch (IOException e4) {
                    }
                }
            } catch (Throwable e222) {
                Log.e(C0307z.f1601a, "Error writing historical recrod file: " + this.f1277a.f1608h, e222);
                this.f1277a.f1612l = true;
                if (openFileOutput != null) {
                    try {
                        openFileOutput.close();
                    } catch (IOException e5) {
                    }
                }
            } catch (Throwable th) {
                this.f1277a.f1612l = true;
                if (openFileOutput != null) {
                    try {
                        openFileOutput.close();
                    } catch (IOException e6) {
                    }
                }
            }
        } catch (Throwable e2222) {
            Log.e(C0307z.f1601a, "Error writing historical recrod file: " + str, e2222);
        }
        return null;
    }

    public /* synthetic */ Object doInBackground(Object[] objArr) {
        return m2461a(objArr);
    }
}
