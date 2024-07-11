/*
 * OpenAI API
 *
 * The OpenAI REST API. Please see https://platform.openai.com/docs/api-reference for more details.
 *
 * OpenAPI spec version: 2.1.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 */
using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using Newtonsoft.Json;

namespace IO.Swagger.Models
{
    /// <summary>
    /// Represents the url or the content of an image generated by the OpenAI API.
    /// </summary>
    [DataContract]
    public partial class Image : IEquatable<Image>
    { 
        /// <summary>
        /// The base64-encoded JSON of the generated image, if &#x60;response_format&#x60; is &#x60;b64_json&#x60;.
        /// </summary>
        /// <value>The base64-encoded JSON of the generated image, if &#x60;response_format&#x60; is &#x60;b64_json&#x60;.</value>

        [DataMember(Name="b64_json")]
        public string B64Json { get; set; }

        /// <summary>
        /// The URL of the generated image, if &#x60;response_format&#x60; is &#x60;url&#x60; (default).
        /// </summary>
        /// <value>The URL of the generated image, if &#x60;response_format&#x60; is &#x60;url&#x60; (default).</value>

        [DataMember(Name="url")]
        public string Url { get; set; }

        /// <summary>
        /// The prompt that was used to generate the image, if there was any revision to the prompt.
        /// </summary>
        /// <value>The prompt that was used to generate the image, if there was any revision to the prompt.</value>

        [DataMember(Name="revised_prompt")]
        public string RevisedPrompt { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Image {\n");
            sb.Append("  B64Json: ").Append(B64Json).Append("\n");
            sb.Append("  Url: ").Append(Url).Append("\n");
            sb.Append("  RevisedPrompt: ").Append(RevisedPrompt).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public string ToJson()
        {
            return JsonConvert.SerializeObject(this, Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="obj">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            return obj.GetType() == GetType() && Equals((Image)obj);
        }

        /// <summary>
        /// Returns true if Image instances are equal
        /// </summary>
        /// <param name="other">Instance of Image to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Image other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    B64Json == other.B64Json ||
                    B64Json != null &&
                    B64Json.Equals(other.B64Json)
                ) && 
                (
                    Url == other.Url ||
                    Url != null &&
                    Url.Equals(other.Url)
                ) && 
                (
                    RevisedPrompt == other.RevisedPrompt ||
                    RevisedPrompt != null &&
                    RevisedPrompt.Equals(other.RevisedPrompt)
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                var hashCode = 41;
                // Suitable nullity checks etc, of course :)
                    if (B64Json != null)
                    hashCode = hashCode * 59 + B64Json.GetHashCode();
                    if (Url != null)
                    hashCode = hashCode * 59 + Url.GetHashCode();
                    if (RevisedPrompt != null)
                    hashCode = hashCode * 59 + RevisedPrompt.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(Image left, Image right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(Image left, Image right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
