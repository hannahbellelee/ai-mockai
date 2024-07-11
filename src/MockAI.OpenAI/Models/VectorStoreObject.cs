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
    /// A vector store is a collection of processed files can be used by the &#x60;file_search&#x60; tool.
    /// </summary>
    [DataContract]
    public partial class VectorStoreObject : IEquatable<VectorStoreObject>
    { 
        /// <summary>
        /// The identifier, which can be referenced in API endpoints.
        /// </summary>
        /// <value>The identifier, which can be referenced in API endpoints.</value>
        [Required]

        [DataMember(Name="id")]
        public string Id { get; set; }

        /// <summary>
        /// The object type, which is always `vector_store`.
        /// </summary>
        /// <value>The object type, which is always `vector_store`.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum ObjectEnum
        {
            /// <summary>
            /// Enum VectorStoreEnum for vector_store
            /// </summary>
            [EnumMember(Value = "vector_store")]
            VectorStoreEnum = 0        }

        /// <summary>
        /// The object type, which is always &#x60;vector_store&#x60;.
        /// </summary>
        /// <value>The object type, which is always &#x60;vector_store&#x60;.</value>
        [Required]

        [DataMember(Name="object")]
        public ObjectEnum? _Object { get; set; }

        /// <summary>
        /// The Unix timestamp (in seconds) for when the vector store was created.
        /// </summary>
        /// <value>The Unix timestamp (in seconds) for when the vector store was created.</value>
        [Required]

        [DataMember(Name="created_at")]
        public int? CreatedAt { get; set; }

        /// <summary>
        /// The name of the vector store.
        /// </summary>
        /// <value>The name of the vector store.</value>
        [Required]

        [DataMember(Name="name")]
        public string Name { get; set; }

        /// <summary>
        /// The total number of bytes used by the files in the vector store.
        /// </summary>
        /// <value>The total number of bytes used by the files in the vector store.</value>
        [Required]

        [DataMember(Name="usage_bytes")]
        public int? UsageBytes { get; set; }

        /// <summary>
        /// Gets or Sets FileCounts
        /// </summary>
        [Required]

        [DataMember(Name="file_counts")]
        public VectorStoreObjectFileCounts FileCounts { get; set; }

        /// <summary>
        /// The status of the vector store, which can be either `expired`, `in_progress`, or `completed`. A status of `completed` indicates that the vector store is ready for use.
        /// </summary>
        /// <value>The status of the vector store, which can be either `expired`, `in_progress`, or `completed`. A status of `completed` indicates that the vector store is ready for use.</value>
        [JsonConverter(typeof(Newtonsoft.Json.Converters.StringEnumConverter))]
        public enum StatusEnum
        {
            /// <summary>
            /// Enum ExpiredEnum for expired
            /// </summary>
            [EnumMember(Value = "expired")]
            ExpiredEnum = 0,
            /// <summary>
            /// Enum InProgressEnum for in_progress
            /// </summary>
            [EnumMember(Value = "in_progress")]
            InProgressEnum = 1,
            /// <summary>
            /// Enum CompletedEnum for completed
            /// </summary>
            [EnumMember(Value = "completed")]
            CompletedEnum = 2        }

        /// <summary>
        /// The status of the vector store, which can be either &#x60;expired&#x60;, &#x60;in_progress&#x60;, or &#x60;completed&#x60;. A status of &#x60;completed&#x60; indicates that the vector store is ready for use.
        /// </summary>
        /// <value>The status of the vector store, which can be either &#x60;expired&#x60;, &#x60;in_progress&#x60;, or &#x60;completed&#x60;. A status of &#x60;completed&#x60; indicates that the vector store is ready for use.</value>
        [Required]

        [DataMember(Name="status")]
        public StatusEnum? Status { get; set; }

        /// <summary>
        /// Gets or Sets ExpiresAfter
        /// </summary>

        [DataMember(Name="expires_after")]
        public VectorStoreExpirationAfter ExpiresAfter { get; set; }

        /// <summary>
        /// The Unix timestamp (in seconds) for when the vector store will expire.
        /// </summary>
        /// <value>The Unix timestamp (in seconds) for when the vector store will expire.</value>

        [DataMember(Name="expires_at")]
        public int? ExpiresAt { get; set; }

        /// <summary>
        /// The Unix timestamp (in seconds) for when the vector store was last active.
        /// </summary>
        /// <value>The Unix timestamp (in seconds) for when the vector store was last active.</value>
        [Required]

        [DataMember(Name="last_active_at")]
        public int? LastActiveAt { get; set; }

        /// <summary>
        /// Set of 16 key-value pairs that can be attached to an object. This can be useful for storing additional information about the object in a structured format. Keys can be a maximum of 64 characters long and values can be a maxium of 512 characters long. 
        /// </summary>
        /// <value>Set of 16 key-value pairs that can be attached to an object. This can be useful for storing additional information about the object in a structured format. Keys can be a maximum of 64 characters long and values can be a maxium of 512 characters long. </value>
        [Required]

        [DataMember(Name="metadata")]
        public Object Metadata { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            var sb = new StringBuilder();
            sb.Append("class VectorStoreObject {\n");
            sb.Append("  Id: ").Append(Id).Append("\n");
            sb.Append("  _Object: ").Append(_Object).Append("\n");
            sb.Append("  CreatedAt: ").Append(CreatedAt).Append("\n");
            sb.Append("  Name: ").Append(Name).Append("\n");
            sb.Append("  UsageBytes: ").Append(UsageBytes).Append("\n");
            sb.Append("  FileCounts: ").Append(FileCounts).Append("\n");
            sb.Append("  Status: ").Append(Status).Append("\n");
            sb.Append("  ExpiresAfter: ").Append(ExpiresAfter).Append("\n");
            sb.Append("  ExpiresAt: ").Append(ExpiresAt).Append("\n");
            sb.Append("  LastActiveAt: ").Append(LastActiveAt).Append("\n");
            sb.Append("  Metadata: ").Append(Metadata).Append("\n");
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
            return obj.GetType() == GetType() && Equals((VectorStoreObject)obj);
        }

        /// <summary>
        /// Returns true if VectorStoreObject instances are equal
        /// </summary>
        /// <param name="other">Instance of VectorStoreObject to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(VectorStoreObject other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            return 
                (
                    Id == other.Id ||
                    Id != null &&
                    Id.Equals(other.Id)
                ) && 
                (
                    _Object == other._Object ||
                    _Object != null &&
                    _Object.Equals(other._Object)
                ) && 
                (
                    CreatedAt == other.CreatedAt ||
                    CreatedAt != null &&
                    CreatedAt.Equals(other.CreatedAt)
                ) && 
                (
                    Name == other.Name ||
                    Name != null &&
                    Name.Equals(other.Name)
                ) && 
                (
                    UsageBytes == other.UsageBytes ||
                    UsageBytes != null &&
                    UsageBytes.Equals(other.UsageBytes)
                ) && 
                (
                    FileCounts == other.FileCounts ||
                    FileCounts != null &&
                    FileCounts.Equals(other.FileCounts)
                ) && 
                (
                    Status == other.Status ||
                    Status != null &&
                    Status.Equals(other.Status)
                ) && 
                (
                    ExpiresAfter == other.ExpiresAfter ||
                    ExpiresAfter != null &&
                    ExpiresAfter.Equals(other.ExpiresAfter)
                ) && 
                (
                    ExpiresAt == other.ExpiresAt ||
                    ExpiresAt != null &&
                    ExpiresAt.Equals(other.ExpiresAt)
                ) && 
                (
                    LastActiveAt == other.LastActiveAt ||
                    LastActiveAt != null &&
                    LastActiveAt.Equals(other.LastActiveAt)
                ) && 
                (
                    Metadata == other.Metadata ||
                    Metadata != null &&
                    Metadata.Equals(other.Metadata)
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
                    if (Id != null)
                    hashCode = hashCode * 59 + Id.GetHashCode();
                    if (_Object != null)
                    hashCode = hashCode * 59 + _Object.GetHashCode();
                    if (CreatedAt != null)
                    hashCode = hashCode * 59 + CreatedAt.GetHashCode();
                    if (Name != null)
                    hashCode = hashCode * 59 + Name.GetHashCode();
                    if (UsageBytes != null)
                    hashCode = hashCode * 59 + UsageBytes.GetHashCode();
                    if (FileCounts != null)
                    hashCode = hashCode * 59 + FileCounts.GetHashCode();
                    if (Status != null)
                    hashCode = hashCode * 59 + Status.GetHashCode();
                    if (ExpiresAfter != null)
                    hashCode = hashCode * 59 + ExpiresAfter.GetHashCode();
                    if (ExpiresAt != null)
                    hashCode = hashCode * 59 + ExpiresAt.GetHashCode();
                    if (LastActiveAt != null)
                    hashCode = hashCode * 59 + LastActiveAt.GetHashCode();
                    if (Metadata != null)
                    hashCode = hashCode * 59 + Metadata.GetHashCode();
                return hashCode;
            }
        }

        #region Operators
        #pragma warning disable 1591

        public static bool operator ==(VectorStoreObject left, VectorStoreObject right)
        {
            return Equals(left, right);
        }

        public static bool operator !=(VectorStoreObject left, VectorStoreObject right)
        {
            return !Equals(left, right);
        }

        #pragma warning restore 1591
        #endregion Operators
    }
}
