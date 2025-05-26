setTimeout(function () {
    // Java.perform(function () {
    //     var gzip = Java.use('java.util.zip.GZIPOutputStream');
    //     gzip.write.overload('[B', 'int', 'int').implementation = function (p0, p1, p2) {
    //         var ret = this.write(p0, p1, p2);
    //         send('{"crypto":"{\\"class_name\\":\\"java.util.zip.GZIPOutputStream\\",\\"method_name\\":\\"write\\",\\"hashcode\\":\\"' + this.hashCode() + '\\",\\"args\\":[\\"' + btoa(p0) + '\\",\\"' + (p1) + '\\",\\"' + (p2) + '\\"],\\"ret\\":\\"\\",\\"stackTrace\\":\\"' + btoa(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())) + '\\"}"}');
    //         return ret;
    //     }
        Java.perform(function () {
            var gzip = Java.use('java.util.zip.GZIPOutputStream');
            gzip.write.overload('[B', 'int', 'int').implementation = function (p0, p1, p2) {
                var ret = this.write(p0, p1, p2);
                if (p1 + p2 === p0.length) { // Check if all data has been written
                    this.close(); // Close the stream after all data has been written
                }
                send('{"crypto":"{\\"class_name\\":\\"java.util.zip.GZIPOutputStream\\",\\"method_name\\":\\"write\\",\\"hashcode\\":\\"' + this.hashCode() + '\\",\\"args\\":[\\"' + btoa(p0) + '\\",\\"' + (p1) + '\\",\\"' + (p2) + '\\"],\\"ret\\":\\"\\",\\"stackTrace\\":\\"' + btoa(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())) + '\\"}"}');
                return ret;
            }

        

        // var bytearray = Java.use('java.io.ByteArrayOutputStream');
        // bytearray.toByteArray.overload().implementation = function() {
        //     var ret = this.toByteArray();
        //     send('{"crypto":"{\\"class_name\\":\\"java.io.ByteArrayOutputStream\\",\\"method_name\\":\\"toByteArray\\",\\"hashcode\\":\\"' + this.hashCode() + '\\",\\"args\\":[],\\"ret\\":\\"' + btoa(ret) + '\\",\\"stackTrace\\":\\"' + btoa(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())) + '\\"}"}');
        //     return ret;
        // }
    });

}, 0);