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
    /// Represents an embedding vector returned by embedding endpoint. 
    /// </summary>
    [DataContract]
    public partial class Embedding : IEquatable<Embedding>
    { 
        /// <summary>
        /// The index of the embedding in the list of embeddings.
        /// </summary>
        /// <value>The index of the embedding in the list of embeddings.</value>
        [Required]

        [DataMember(Name="index")]
        public int? Index { get; set; }

        /// <summary>
        /// The embedding vector, which is a list of floats. The length of vector depends on the model as listed in the [embedding guide](/docs/guides/embeddings). 
        /// </summary>
        /// <value>The embedding vector, which is a list of floats. The length of vector depends on the model as listed in the [embedding guide](/docs/guides/embeddings). </value>
        [Required]

        [DataMember(Name="embedding")]
        public List<decimal?> _Embedding { get; set; }

        /// <summary>
        /// The object type, which is always \"embedding\".
        /// </summary>
        /// <value>The object type, which is always \"embedding\".</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum ObjectEnum
        {
            /// <summary>
            /// Enum EmbeddingEnum for embedding
            /// </summary>
            [EnumMember(Value = "embedding")]
            EmbeddingEnum = 0        }

        /// <summary>
        /// The object type, which is always \&quot;embedding\&quot;.
        /// </summary>
        /// <value>The object type, which is always \&quot;embedding\&quot;.</value>
        [Required]

        [DataMember(Name="object")]
        public ObjectEnum? _Object { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class Embedding {\n");
            sb.Append("  Index: ").Append(Index).Append("\n");
            sb.Append("  _Embedding: ").Append(_Embedding).Append("\n");
            sb.Append("  _Object: ").Append(_Object).Append("\n");
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
            return obj.GetType() == GetType() && Equals((Embedding)obj);
        }

        /// <summary>
        /// Returns true if Embedding instances are equal
        /// </summary>
        /// <param name="other">Instance of Embedding to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(Embedding other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Index == other.Index ||
                    Index != null &&
                    Index.Equals(other.Index)
                ) && 
                (
                    _Embedding == other._Embedding ||
                    _Embedding != null &&
                    _Embedding.SequenceEqual(other._Embedding)
                ) && 
                (
                    _Object == other._Object ||
                    _Object != null &&
                    _Object.Equals(other._Object)
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
                    if (Index != null)
                    hashCode = hashCode * 59 + Index.GetHashCode();
                    if (_Embedding != null)
                    hashCode = hashCode * 59 + _Embedding.GetHashCode();
                    if (_Object != null)
                    hashCode = hashCode * 59 + _Object.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(Embedding left, Embedding right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(Embedding left, Embedding right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}